/* SPDX-License-Identifier: GPL-2.0 */
/*
 * foresight_sched - userspace control plane for the foresight_sched
 * workload-class-aware sched_ext scheduler.
 *
 * The BPF (kernel) side lives in foresight_sched.bpf.c (Writer A); this
 * file (Writer B) is the userspace control plane that opens, loads, seeds,
 * attaches, monitors and cleanly tears the scheduler down. The lifecycle
 * mirrors the in-tree reference tools/sched_ext/scx_simple.c, and numeric
 * option parsing follows the pattern of tools/sched_ext/scx_qmap.c:
 *
 *	SCX_OPS_OPEN() -> getopt -> [SCX_OPS_LOAD steps] -> seed task_class
 *	-> SCX_OPS_ATTACH() -> 1 Hz stats loop -> bpf_link__destroy()
 *	-> UEI_REPORT() -> skeleton destroy -> (restart if kernel asked)
 *
 * Contract with foresight_sched.bpf.c (compile-time enforced):
 * This file includes the bpftool-generated "foresight_sched.bpf.skel.h"
 * exactly the way scx_simple.c includes "scx_simple.bpf.skel.h". The
 * generated skeleton must therefore expose:
 *	- ops variable name "foresight_sched" (-> skel->struct_ops.foresight_sched)
 *	- map "task_class": BPF hash, key u32 pid, value u8 class
 *	  (0 = normal, 1 = interactive, 2 = batch)
 *	- map "stats": BPF array, key u32 0..2, value u64 enqueue counters
 *	- UEI_DEFINE(uei) exit-info block named "uei"
 * If Writer A renames any of these, this file fails to COMPILE (unknown
 * skeleton struct field) - the loudest failure we can engineer. Map
 * key/value sizes and the stats map type are additionally verified at
 * runtime in verify_map_contract().
 *
 * Phase 0 vs Phase 1 - the classification split:
 *	Phase 0 (this file): STATIC CLI SEEDING. The task_class map starts
 *	EMPTY by default. We deliberately seed nothing per-pid on startup:
 *	userspace cannot know which pids will matter before the scheduler
 *	even runs, and scanning /proc for comm names would be racy and
 *	outside the reference API set. Every task therefore falls to class 0
 *	(normal) unless the operator explicitly pins pids with the
 *	repeatable options
 *	    --interactive PID	(class 1)
 *	    --batch PID		(class 2)
 *	which are inserted into task_class AFTER load (that is when the map
 *	fd starts existing) and BEFORE attach (so no task is ever scheduled
 *	by us while the map is still being filled - zero misclassification
 *	window). The maintainer can validate the whole pipeline by running a
 *	compile job with --batch <pid> and watching the batch counter climb
 *	in the stats line.
 *
 *	PID namespace caveat (validated the hard way in the dev VM, which
 *	runs WSL2 with systemd): the BPF side classifies tasks by their
 *	kernel-GLOBAL pid (p->pid), so inside a pid namespace the pid
 *	printed by ps/$! is the namespaced one: it will not match the
 *	INTENDED task, and - because the map key is the global pid - the
 *	seed can instead classify a DIFFERENT, unrelated task (whatever
 *	init-namespace task owns that pid number). In containers the
 *	global pid is listed in /proc/<pid>/status (NSpid);
 *	in WSL2's distro namespace even NSpid hides it (BPF saw pids ~+160
 *	higher than ps) - there, learn the global pid from a BPF task view
 *	(e.g. the "pids" line of 'bpftool map show', which reports
 *	init-namespace pids) or run the test outside the namespace. Every
 *	sched_ext tool shares this property (scx_qmap's -d PID behaves
 *	the same), so it is warned about, not worked around. At startup
 *	this program detects the namespace mismatch via /proc/self/ns/pid
 *	vs /proc/1/ns/pid and prints one loud warning when pids are given.
 *	Phase 1 (future, Foresight daemon): LIVE classification. A daemon
 *	will watch /proc, match comm names against the static rules table
 *	below, and update task_class at runtime. The rules table in this
 *	file is the shared Phase-1 contract: it documents the intended
 *	comm -> class mapping and is printed under -v, but it is NOT used
 *	for seeding in Phase 0 - that is the point of the split.
 *
 * Judgment calls (deliberate deviations from scx_simple.c, all flagged
 * for the reviewers):
 *	1. SCX_OPS_LOAD() is expanded by hand into its two constituent
 *	   statements (UEI_SET_SIZE + __load, see include/scx/compat.h) so a
 *	   load failure can print a message naming the likely culprit file.
 *	   The macro itself only SCX_BUG()s with "Failed to load skel".
 *	2. --interactive/--batch require long options (project spec), so we
 *	   use getopt_long() (standard glibc, same family as the reference
 *	   getopt()); short aliases -i/-b are provided.
 *	3. read_stats() zeroes its scratch buffer before lookup so it reads
 *	   correctly whether the "stats" map is a plain BPF_MAP_TYPE_ARRAY
 *	   or a BPF_MAP_TYPE_PERCPU_ARRAY (scx_simple assumes percpu).
 *	4. The number of possible CPUs is computed once and checked (the
 *	   reference re-reads it every second and assert()s).
 *	5. The kernel-restart path (SCX_ECODE_ACT_RESTART) re-seeds the class
 *	   map after every reload; the CLI pid lists live before the
 *	   restart label so they survive the backward goto.
 *	6. libbpf map introspection (bpf_map__key_size/__value_size/__type)
 *	   verifies the map contract at runtime; same libbpf API family as
 *	   the mandated bpf_map__update_elem(), used to fail loudly instead
 *	   of corrupting the stats scratch buffer.
 *
 * Build: mirrors the reference Makefile rule - bpftool "gen skeleton
 * foresight_sched.bpf.o name foresight_sched" (the explicit name makes
 * bpftool emit the foresight_sched_* symbols this file expects, exactly
 * as the reference Makefile passes name $(subst .bpf.skel.h,,$(sched)))
 * writes foresight_sched.bpf.skel.h next to this file before gcc
 * compiles this file against libbpf with -Wall -Werror.
 *
 * Based on tools/sched_ext/scx_simple.c and scx_qmap.c from the Linux
 * kernel tree (GPL-2.0, Copyright Meta Platforms, Tejun Heo, David
 * Vernet). foresight-sched project, Phase 0, 2026.
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <libgen.h>
#include <getopt.h>
#include <sys/stat.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "foresight_sched.bpf.skel.h"

const char help_fmt[] =
"A workload-class-aware sched_ext scheduler (userspace control plane).\n"
"\n"
"See the top-of-file comment in foresight_sched.bpf.c for BPF-side details.\n"
"\n"
"Usage: %s [--interactive PID]... [--batch PID]... [-v] [-h]\n"
"\n"
"  --interactive PID, -i PID   Pin PID to class 1 (interactive). Repeatable;\n"
"                              repeats within the class: last option wins.\n"
"                              A PID given as BOTH --interactive and\n"
"                              --batch is classified as BATCH (batch is\n"
"                              seeded after interactive).\n"
"  --batch PID, -b PID         Pin PID to class 2 (batch). Repeatable; last\n"
"                              option wins within the class.\n"
"  -v, --verbose               Print libbpf debug messages and the Phase 1\n"
"                              comm-name classification rules table.\n"
"  -h, --help                  Display this help and exit\n"
"\n"
"Phase 0 starts with an EMPTY class map: every task not pinned above runs\n"
"as class 0 (normal). PIDs are thread ids as shown by ps/top; the BPF side\n"
"matches kernel-global pids, so inside pid namespaces (containers, WSL2's\n"
"distro namespace) a ps pid may not match: containers can read the global\n"
"pid from /proc/<pid>/status NSpid, WSL2 needs a BPF task view (e.g. the\n"
"pids line of 'bpftool map show') or a test run outside the namespace.\n";

/*
 * Workload classes. These values are the wire format of the task_class
 * map value (u8) and MUST match the BPF side:
 *	0 = normal (default), 1 = interactive, 2 = batch.
 * FORESIGHT_NR_CLASSES is the sentinel equal to the number of classes,
 * i.e. the number of "stats" map keys (0..2).
 */
enum foresight_class {
	FORESIGHT_CLASS_NORMAL		= 0,
	FORESIGHT_CLASS_INTERACTIVE	= 1,
	FORESIGHT_CLASS_BATCH		= 2,
	FORESIGHT_NR_CLASSES,		/* sentinel: one stats slot per class */
};

/*
 * Capacity of each --interactive/--batch pid list. 256 pinned tasks is
 * far beyond any honest Phase 0 test; failing loudly here beats a silent
 * buffer overrun any day.
 */
#define MAX_SEED_PIDS 256

/*
 * PHASE 1 pinned-map contract with the Foresight classification daemon:
 * the loader pins task_class and pid_probe under /sys/fs/bpf/foresight
 * so a separate process can translate namespace pids (via pid_probe)
 * and live-update classifications (via task_class) using bpftool.
 * Pins exist only while the scheduler runs; teardown always unpins.
 */
#define PIN_DIR			"/sys/fs/bpf/foresight"
#define PIN_TASK_CLASS		(PIN_DIR "/task_class")
#define PIN_PID_PROBE		(PIN_DIR "/pid_probe")

/*
 * Phase 1 classification rules table: /proc/<pid>/comm (at most 15 chars;
 * kernel TASK_COMM_LEN is 16 including the NUL) -> class.
 *
 * CONCEPT/CONTRACT ONLY in Phase 0: printed under -v, never used to seed
 * the map (pids are not knowable in advance - see the header comment).
 * The Phase 1 Foresight daemon will match task comm names against this
 * table and update task_class live.
 */
struct class_rule {
	const char	*comm;
	__u8		class;
};

static const struct class_rule class_rules[] = {
	/* Latency-sensitive: shells, editors, remote sessions */
	{ "bash",	FORESIGHT_CLASS_INTERACTIVE },
	{ "zsh",	FORESIGHT_CLASS_INTERACTIVE },
	{ "ssh",	FORESIGHT_CLASS_INTERACTIVE },
	{ "vim",	FORESIGHT_CLASS_INTERACTIVE },
	{ "emacs",	FORESIGHT_CLASS_INTERACTIVE },
	/* Throughput-oriented: build machinery and compilers */
	{ "make",	FORESIGHT_CLASS_BATCH },
	{ "ninja",	FORESIGHT_CLASS_BATCH },
	{ "gcc",	FORESIGHT_CLASS_BATCH },
	{ "cc1",	FORESIGHT_CLASS_BATCH },	/* gcc's per-TU worker */
	{ "ld",		FORESIGHT_CLASS_BATCH },
	{ "rustc",	FORESIGHT_CLASS_BATCH },
};

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

/*
 * SIGINT/SIGTERM handler, mirrored from scx_simple.c: just set the flag.
 * The stats loop notices it within one second and takes the normal clean
 * teardown path (link destroy -> UEI report -> skeleton destroy). The
 * reference ignores the signal number parameter; the (void) cast
 * additionally keeps -Wextra builds quiet about that.
 */
static void sigint_handler(int signo)
{
	(void)signo;
	exit_req = 1;
}

/* Human-readable class name for messages and the rules dump. */
static const char *class_name(__u8 class)
{
	switch (class) {
	case FORESIGHT_CLASS_NORMAL:
		return "normal";
	case FORESIGHT_CLASS_INTERACTIVE:
		return "interactive";
	case FORESIGHT_CLASS_BATCH:
		return "batch";
	default:
		return "unknown";
	}
}

/*
 * Iterate the static rules table. In Phase 0 this only documents the
 * Phase 1 comm -> class contract for the operator (printed with -v so
 * the default stats output stays as clean as scx_simple's); it never
 * writes the map. Keeping the walk as real code means the table cannot
 * rot while Phase 1 is being written.
 */
static void print_class_rules(void)
{
	size_t i;

	printf("foresight_sched: Phase 1 comm-name classification rules "
	       "(documentation only; NOT used for Phase 0 seeding):\n");
	for (i = 0; i < sizeof(class_rules) / sizeof(class_rules[0]); i++)
		printf("  %-12s -> class %u (%s)\n",
		       class_rules[i].comm,
		       (unsigned)class_rules[i].class,
		       class_name(class_rules[i].class));
	fflush(stdout);
}

/*
 * Parse a pid from a command line argument. strtoul() with base 0, the
 * same convention scx_qmap.c uses for its numeric options (0x... works).
 * glibc strtoul silently accepts a leading '-' and wraps the result to
 * a huge unsigned value, which the u32 range check below rejects; pid 0
 * is the idle task (never dispatched through sched_ext), so accepting
 * it would only hide typos.
 */
static int parse_pid_arg(const char *arg, __u32 *pid)
{
	char *endp = NULL;
	unsigned long val;

	if (!arg || !arg[0])
		return -1;

	val = strtoul(arg, &endp, 0);
	if (endp == arg || *endp != '\0')
		return -1;		/* no digits at all / trailing junk */
	if (val == 0 || val > 0xFFFFFFFFUL)
		return -1;		/* idle task / does not fit the u32 key */

	*pid = (__u32)val;
	return 0;
}

/* Append one parsed pid to a seed list, refusing to overrun the cap. */
static int collect_pid(__u32 *pids, int *nr, const char *optname, __u32 pid)
{
	if (*nr >= MAX_SEED_PIDS) {
		fprintf(stderr,
			"foresight_sched: too many --%s pids (max %d); raise MAX_SEED_PIDS and rebuild\n",
			optname, MAX_SEED_PIDS);
		return -1;
	}
	pids[(*nr)++] = pid;
	return 0;
}

/*
 * PID-namespace detection (reviewer-requested): if this process's pid
 * namespace differs from init's, CLI pids are namespace-local numbers
 * while the BPF side matches kernel-GLOBAL pids - a seed intended for
 * one task can instead classify a completely unrelated one. Warn once,
 * loudly, whenever pids were requested in that situation.
 */
static void warn_if_pid_namespaced(int nr_seeded)
{
	char self_ns[128], init_ns[128];
	ssize_t a, b;

	if (!nr_seeded)
		return;
	a = readlink("/proc/self/ns/pid", self_ns, sizeof(self_ns) - 1);
	b = readlink("/proc/1/ns/pid", init_ns, sizeof(init_ns) - 1);
	if (a <= 0 || b <= 0)
		return;				/* cannot tell - stay quiet */
	self_ns[a] = '\0';
	init_ns[b] = '\0';
	if (strcmp(self_ns, init_ns) != 0)
		fprintf(stderr,
			"foresight_sched: WARNING: running inside a pid namespace (self=%s init=%s): requested pids are namespace-local but the BPF side matches kernel-GLOBAL pids, so seeds may classify unrelated tasks (see pid-namespace caveat in the file header)\n",
			self_ns, init_ns);
}

/*
 * Release the pinned paths on every post-pin exit path (error or
 * normal teardown), so a crashed or killed loader never leaves a stale
 * pin for the next run to trip over. Both unpins are best-effort.
 */
static void unpin_maps(struct foresight_sched *skel)
{
	bpf_map__unpin(skel->maps.task_class, PIN_TASK_CLASS);
	bpf_map__unpin(skel->maps.pid_probe, PIN_PID_PROBE);
}

/*
 * The kernel side is written in parallel (Writer A) against a written
 * contract. Skeleton field NAMES are enforced at compile time, but map
 * key/value sizes and the stats map TYPE are not, and a mismatch would
 * either break every update or - worse - make the kernel copy more bytes
 * per stats lookup than our scratch buffer holds. Verify the contract at
 * runtime, right after load, and refuse to attach on drift.
 */
static int verify_map_contract(struct foresight_sched *skel)
{
	size_t key_sz, val_sz;
	enum bpf_map_type type;

	/* task_class: HASH, key u32 pid -> value u8 class. */
	key_sz = bpf_map__key_size(skel->maps.task_class);
	val_sz = bpf_map__value_size(skel->maps.task_class);
	type = bpf_map__type(skel->maps.task_class);
	if (key_sz != sizeof(__u32) || val_sz != sizeof(__u8) ||
	    type != BPF_MAP_TYPE_HASH) {
		fprintf(stderr,
			"foresight_sched: task_class contract violated: expected HASH key u32 (got type %d, %zu bytes), value u8 (got %zu bytes); fix the task_class declaration in foresight_sched.bpf.c\n",
			(int)type, key_sz, val_sz);
		return -1;
	}
	/* Capacity must cover every seed we are about to write. */
	if (bpf_map__max_entries(skel->maps.task_class) < MAX_SEED_PIDS) {
		fprintf(stderr,
			"foresight_sched: task_class contract violated: max_entries=%u < %d seeds possible; fix the task_class declaration in foresight_sched.bpf.c\n",
			bpf_map__max_entries(skel->maps.task_class),
			MAX_SEED_PIDS);
		return -1;
	}

	/*
	 * stats: key u32 0..2 -> value u64 counters. Both plain and percpu
	 * arrays are fine (read_stats handles either); anything else is not.
	 */
	key_sz = bpf_map__key_size(skel->maps.stats);
	val_sz = bpf_map__value_size(skel->maps.stats);
	type = bpf_map__type(skel->maps.stats);
	if (bpf_map__max_entries(skel->maps.stats) < FORESIGHT_NR_CLASSES) {
		fprintf(stderr,
			"foresight_sched: stats contract violated: max_entries=%u < %d class slots; lookups would return ENOENT and read 0 forever; fix the stats declaration in foresight_sched.bpf.c\n",
			bpf_map__max_entries(skel->maps.stats),
			FORESIGHT_NR_CLASSES);
		return -1;
	}
	if (key_sz != sizeof(__u32) || val_sz != sizeof(__u64) ||
	    (type != BPF_MAP_TYPE_ARRAY && type != BPF_MAP_TYPE_PERCPU_ARRAY)) {
		fprintf(stderr,
			"foresight_sched: stats contract violated: expected key u32 (got %zu), value u64 (got %zu), type ARRAY or PERCPU_ARRAY (got %d); fix the stats declaration in foresight_sched.bpf.c\n",
			key_sz, val_sz, (int)type);
		return -1;
	}

	return 0;
}

/*
 * Insert one classification into the task_class map. Runs AFTER load
 * (the map fd only exists then) and BEFORE attach. BPF_ANY creates or
 * overwrites, which is what gives "last option wins" semantics for
 * repeated pids on the command line.
 */
static int seed_task_class(struct foresight_sched *skel, __u32 pid, __u8 class)
{
	int ret;

	ret = bpf_map__update_elem(skel->maps.task_class,
				  &pid, sizeof(pid),
				  &class, sizeof(class),
				  BPF_ANY);
	if (ret) {
		fprintf(stderr,
			"foresight_sched: task_class update failed for pid=%u class=%u (%s): ret=%d (%s); expected a loaded BPF hash { u32 pid -> u8 class } from foresight_sched.bpf.c\n",
			pid, (unsigned)class, class_name(class), ret,
			strerror(-ret));
		return ret;
	}
	return 0;
}

/* Seed a whole CLI pid list; returns the first failure, if any. */
static int seed_class_map(struct foresight_sched *skel, const __u32 *pids,
			  int nr_pids, __u8 class)
{
	int i;

	for (i = 0; i < nr_pids; i++) {
		int ret = seed_task_class(skel, pids[i], class);

		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Sum the per-class enqueue counters out of the stats array map.
 * Mirrors scx_simple.c's read_stats(): each stats key 0..2 maps to a
 * per-CPU slab (u64 * nr_cpus) when the map is PERCPU_ARRAY, and to a
 * single u64 when it is a plain ARRAY. Because the kernel writes only
 * value_size bytes per key in the plain case, the scratch buffer is
 * zeroed first so the per-CPU summation below is correct for BOTH map
 * flavors (scx_simple relies on the kernel filling every slot).
 */
static void read_stats(struct foresight_sched *skel, int nr_cpus, __u64 *stats)
{
	static bool warned_lookup;
	__u64 cnts[FORESIGHT_NR_CLASSES][nr_cpus];	/* VLA, as in scx_simple */
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * FORESIGHT_NR_CLASSES);
	memset(cnts, 0, sizeof(cnts));

	for (idx = 0; idx < FORESIGHT_NR_CLASSES; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0) {
			/*
			 * scx_simple just keeps going with zeros; we also
			 * warn once so a broken stats map cannot fail
			 * invisibly every second.
			 */
			if (!warned_lookup) {
				warned_lookup = true;
				fprintf(stderr,
					"foresight_sched: stats lookup failed for key %u (ret=%d, %s); missing keys read as zero - check the stats array in foresight_sched.bpf.c\n",
					idx, ret, strerror(-ret));
			}
			continue;
		}
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "interactive", required_argument,	NULL, 'i' },
		{ "batch",       required_argument,	NULL, 'b' },
		{ "verbose",     no_argument,		NULL, 'v' },
		{ "help",        no_argument,		NULL, 'h' },
		{ NULL,          0,			NULL,  0  },
	};
	struct foresight_sched *skel;
	struct bpf_link *link;
	int opt;
	int err;
	int nr_cpus;
	int nr_interactive = 0;
	int nr_batch = 0;
	__u32 interactive_pids[MAX_SEED_PIDS];
	__u32 batch_pids[MAX_SEED_PIDS];
	__u64 ecode;
	time_t start_time = time(NULL);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	/*
	 * SCX_OPS_OPEN() (include/scx/compat.h) opens the skeleton, records
	 * the CPU hotplug sequence number and verifies the running kernel
	 * is new enough. It exits loudly via SCX_BUG if the kernel is too
	 * old or opening fails, so past this point skel is non-NULL.
	 */
	skel = SCX_OPS_OPEN(foresight_sched, foresight_sched);

	/*
	 * Reviewer-requested hardening: SCX_OPS_OPEN populates the
	 * SCX_SLICE_DFL rodata from vmlinux BTF (via SCX_ENUM_INIT). If
	 * that silent step ever stops happening (e.g. someone hand-expands
	 * the OPEN macro), every task would get a 0 slice - fail loudly
	 * here instead of scheduling with a zero slice.
	 */
	SCX_BUG_ON(!skel->rodata->__SCX_SLICE_DFL,
		   "SCX_SLICE_DFL not populated by SCX_OPS_OPEN");

	/*
	 * Option parsing runs after open, exactly like scx_simple.c. On a
	 * kernel-initiated restart (goto restart below) getopt_long() has
	 * already consumed argv, so this loop falls straight through and
	 * the pid lists parsed here survive intact for re-seeding. Note:
	 * returning here without __destroy() mirrors the reference; an
	 * opened-but-not-loaded skeleton holds no kernel BPF fds, so
	 * nothing leaks beyond process exit.
	 */
	while ((opt = getopt_long(argc, argv, "i:b:vh", long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
		case 'b': {
			__u32 pid;

			if (parse_pid_arg(optarg, &pid)) {
				fprintf(stderr,
					"foresight_sched: --%s expects a pid in 1..4294967295, got '%s' (see -h)\n",
					opt == 'i' ? "interactive" : "batch",
					optarg);
				return EXIT_FAILURE;
			}
			if (opt == 'i') {
				if (collect_pid(interactive_pids,
						&nr_interactive,
						"interactive", pid))
					return EXIT_FAILURE;
			} else {
				if (collect_pid(batch_pids, &nr_batch,
						"batch", pid))
					return EXIT_FAILURE;
			}
			break;
		}
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	if (verbose)
		print_class_rules();

	/*
	 * Deliberate deviation, flagged for review: this is SCX_OPS_LOAD()
	 * from include/scx/compat.h expanded into its two statements,
	 *	UEI_SET_SIZE(skel, foresight_sched, uei);
	 *	SCX_BUG_ON(foresight_sched__load(skel), "Failed to load skel");
	 * so that a load failure can name the likely culprit. libbpf has
	 * already printed the full verifier log to stderr through
	 * libbpf_print_fn above. The load steps themselves are unchanged.
	 */
	UEI_SET_SIZE(skel, foresight_sched, uei);
	err = foresight_sched__load(skel);
	if (err) {
		fprintf(stderr,
			"foresight_sched: failed to load the BPF scheduler (ret=%d). Full libbpf/verifier log above; the most likely cause is a verifier rejection or a missing/renamed map or ops in the kernel-side file foresight_sched.bpf.c\n",
			err);
		foresight_sched__destroy(skel);
		return EXIT_FAILURE;
	}

	/* Fail fast - before attach - on any drift from the map contract. */
	if (verify_map_contract(skel)) {
		foresight_sched__destroy(skel);
		return EXIT_FAILURE;
	}

	/*
	 * PHASE 1 (maintainer addition): pin the two maps for the Foresight
	 * classification daemon. Stale pins from a crashed run are unlinked
	 * first; every failure path below unwinds the pins it created.
	 */
	mkdir(PIN_DIR, 0755);			/* idempotent */
	unlink(PIN_TASK_CLASS);
	unlink(PIN_PID_PROBE);
	if (bpf_map__pin(skel->maps.task_class, PIN_TASK_CLASS)) {
		fprintf(stderr,
			"foresight_sched: failed to pin task_class at %s (is /sys/fs/bpf mounted as bpffs? errno=%d)\n",
			PIN_TASK_CLASS, errno);
		foresight_sched__destroy(skel);
		return EXIT_FAILURE;
	}
	if (bpf_map__pin(skel->maps.pid_probe, PIN_PID_PROBE)) {
		fprintf(stderr,
			"foresight_sched: failed to pin pid_probe at %s (errno=%d)\n",
			PIN_PID_PROBE, errno);
		bpf_map__unpin(skel->maps.task_class, PIN_TASK_CLASS);
		foresight_sched__destroy(skel);
		return EXIT_FAILURE;
	}

	/*
	 * Per-CPU stats summation needs the number of possible CPUs. It is
	 * stable for the life of the process, so compute and check it once
	 * here instead of per iteration (scx_simple re-reads it every
	 * second and assert()s).
	 */
	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus <= 0) {
		fprintf(stderr,
			"foresight_sched: libbpf_num_possible_cpus() failed (ret=%d); cannot read stats safely\n",
			nr_cpus);
		unpin_maps(skel);
		foresight_sched__destroy(skel);
		return EXIT_FAILURE;
	}

	/*
	 * PID-namespace guard: loud one-shot warning when CLI pids were
	 * requested from inside a namespace (see file header caveat).
	 */
	warn_if_pid_namespaced(nr_interactive + nr_batch);

	/*
	 * PHASE 0 SEEDING - the only writes to task_class in this program.
	 * Empty by default (both lists are empty unless -i/-b were given):
	 * every unlisted task simply runs as class 0 (normal). Runs after
	 * load (map fd exists), before attach (zero misclassification
	 * window), and every return code is checked - a seed failure aborts
	 * before we ever take over scheduling. PIDs must be the
	 * kernel-global ones (see the pid namespace caveat in the header).
	 */
	err = seed_class_map(skel, interactive_pids, nr_interactive,
			     FORESIGHT_CLASS_INTERACTIVE);
	if (!err)
		err = seed_class_map(skel, batch_pids, nr_batch,
				     FORESIGHT_CLASS_BATCH);
	if (err) {
		unpin_maps(skel);
		foresight_sched__destroy(skel);
		return EXIT_FAILURE;
	}

	printf("foresight_sched: Phase 0 class map seeded: interactive=%d batch=%d; all other tasks run as class 0 (normal)\n",
	       nr_interactive, nr_batch);
	fflush(stdout);

	/*
	 * Honor a Ctrl-C that arrived during load/seeding: never take over
	 * scheduling after the user asked to quit (reviewer finding).
	 */
	if (exit_req) {
		unpin_maps(skel);
		foresight_sched__destroy(skel);
		return 0;
	}

	/*
	 * Attach the struct_ops. SCX_OPS_ATTACH() (compat.h) calls the
	 * skeleton's attach-all, which auto-attaches the pid_probe
	 * tracepoint (SEC("tp/...") programs are auto-attachable) AND
	 * returns the struct_ops link. Phase 1 lesson learned the hard
	 * way: do NOT attach the tracepoint manually as well - the
	 * duplicate attach fails with -EEXIST and SCX_BUG exits without
	 * cleanup, orphaning the pins.
	 */
	link = SCX_OPS_ATTACH(skel, foresight_sched, foresight_sched);

	/*
	 * PHASE 1: verify the auto-attached pid_probe landed; without it
	 * the daemon cannot translate namespace pids - a hard error.
	 */
	if (!skel->links.record_exec_pid) {
		fprintf(stderr,
			"foresight_sched: pid_probe tracepoint failed to auto-attach\n");
		bpf_link__destroy(link);
		unpin_maps(skel);
		foresight_sched__destroy(skel);
		return EXIT_FAILURE;
	}

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[FORESIGHT_NR_CLASSES];
		time_t now = time(NULL);
		/*
		 * Seconds since control-plane start. time() is the smallest
		 * standard C tool that answers "how long have we been up";
		 * guard against a backwards clock step instead of printing
		 * a wrapped value.
		 */
		__u64 elapsed = now >= start_time ? (__u64)(now - start_time) : 0;

		read_stats(skel, nr_cpus, stats);
		printf("foresight_sched: enq normal=%llu interactive=%llu batch=%llu elapsed=%llus\n",
		       stats[FORESIGHT_CLASS_NORMAL],
		       stats[FORESIGHT_CLASS_INTERACTIVE],
		       stats[FORESIGHT_CLASS_BATCH],
		       elapsed);
		fflush(stdout);
		sleep(1);
	}

	/*
	 * Clean unload, mirrored from scx_simple.c: destroy the link (the
	 * kernel unregisters the scheduler; ops.exit then records
	 * SCX_EXIT_UNREG into uei, so UEI_REPORT prints the familiar
	 * "EXIT: unregistered from user space"), report the exit info,
	 * destroy the skeleton, and honor a kernel restart request (e.g.
	 * CPU hotplug) by jumping back to restart. The class map is
	 * re-seeded after the reload because the pid lists parsed above
	 * live outside the restart cycle.
	 */
	/*
	 * PHASE 1 teardown: the skeleton destroy below closes the
	 * tracepoint link too; release the pinned paths (the daemon sees
	 * them vanish and can exit cleanly), then the standard scx
	 * teardown.
	 */
	unpin_maps(skel);
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	foresight_sched__destroy(skel);

	/* Never restart after the user asked to quit (reviewer finding). */
	if (UEI_ECODE_RESTART(ecode) && !exit_req)
		goto restart;

	/*
	 * Mirror the ops exit code into the process exit code so scripts
	 * can detect a kernel-initiated teardown (e.g. SCX_EXIT_ERROR).
	 */
	return UEI_ECODE_USER(ecode) ? 1 : 0;
}
