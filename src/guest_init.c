// SPDX-License-Identifier: GPL-2.0
/*
 * The guest init of Cloche's microVM backend.
 *
 * The kernel runs this program as PID 1 from an initramfs that the host
 * built for one run. The initramfs holds the program at /init, the sandbox
 * description at /cloche/spec and the seccomp filter at
 * /cloche/seccomp.bpf. Two virtio block devices are attached: an ext4
 * image labelled cloche-in that holds the inputs, read-only, and a raw
 * device that receives the outputs.
 *
 * The init connects to the host over vsock and says "ready". It mounts
 * the inputs, builds the sandbox filesystem on a tmpfs at /sandbox, and
 * starts the program in new mount, PID, UTS and IPC namespaces, as PID 1
 * of its own PID namespace. The program gets /sandbox as its root, the
 * umask 022, no capabilities, the resource limits, no_new_privs and the
 * seccomp filter, exactly as the namespace backend gives them.
 *
 * When the program exits with status 0, the init writes every output to
 * the output device as a cpio archive in the newc format, followed by the
 * TRAILER!!! entry, and flushes it. It then sends one last line, "exited
 * N", "killed N" or "error MESSAGE", and powers the machine off.
 *
 * The spec is a list of NUL-terminated words. Each record is a keyword
 * followed by its fields:
 *
 *   program PATH | arg WORD | env NAME=VALUE | cwd PATH | hostname NAME
 *   id UID GID | rlimit RESOURCE SOFT HARD | output NAME PATH
 *   mount KIND DESTINATION SOURCE FLAGS DATA | port PORT | end
 *
 * KIND is tmpfs, bind or proc. SOURCE and DATA may be empty, and FLAGS is
 * the mount flags as a decimal number.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/vm_sockets.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SPEC_PATH "/cloche/spec"
#define FILTER_PATH "/cloche/seccomp.bpf"
#define INPUT_LABEL "cloche-in"
#define ROOT "/sandbox"
#define INPUTS "/inputs"
#define MAX_ITEMS 4096
#define BUFFER_SIZE (1 << 16)

struct mount_entry {
	const char *kind;
	const char *destination;
	const char *source;
	unsigned long flags;
	const char *data;
};

struct rlimit_entry {
	int resource;
	struct rlimit value;
};

struct output_entry {
	const char *name;
	const char *path;
};

static const char *program;
static const char *cwd = "/";
static const char *hostname = "localhost";
static uid_t uid;
static gid_t gid;
static unsigned int port = 1024;
static const char *args[MAX_ITEMS + 2];
static size_t nargs;
static const char *envs[MAX_ITEMS + 1];
static size_t nenvs;
static struct mount_entry mounts[MAX_ITEMS];
static size_t nmounts;
static struct rlimit_entry rlimits[16];
static size_t nrlimits;
static struct output_entry outputs[MAX_ITEMS];
static size_t noutputs;
static struct sock_fprog filter;

static int host = -1;
static int child_errors = -1;

static void __attribute__((noreturn)) power_off(void)
{
	if (host >= 0)
		close(host);
	sync();
	reboot(RB_POWER_OFF);
	reboot(RB_AUTOBOOT);
	for (;;)
		pause();
}

static void send_line(const char *text)
{
	size_t length = strlen(text);

	if (strncmp(text, "error ", 6) == 0)
		fprintf(stderr, "cloche-init: %s", text);
	while (host >= 0 && length > 0) {
		ssize_t written = write(host, text, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		text += written;
		length -= (size_t)written;
	}
}

static void __attribute__((noreturn, format(printf, 1, 2))) fail(const char *format, ...)
{
	char line[4096];
	int used = snprintf(line, sizeof(line), "error ");
	va_list list;

	va_start(list, format);
	used += vsnprintf(line + used, sizeof(line) - (size_t)used - 1, format, list);
	va_end(list);
	if (used > (int)sizeof(line) - 2)
		used = (int)sizeof(line) - 2;
	line[used] = '\n';
	line[used + 1] = '\0';
	for (char *c = line + 6; c < line + used; c++)
		if (*c == '\n')
			*c = ' ';
	if (child_errors >= 0) {
		/* In the program's child, before exec: the init reports it. */
		ssize_t ignored = write(child_errors, line + 6, (size_t)used - 6);

		(void)ignored;
		_exit(127);
	}
	send_line(line);
	power_off();
}

static char *read_file(const char *path, size_t *size)
{
	struct stat info;
	char *data;
	size_t done = 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0 || fstat(fd, &info) < 0)
		fail("cannot read %s: %s", path, strerror(errno));
	data = malloc((size_t)info.st_size + 1);
	if (data == NULL)
		fail("out of memory");
	while (done < (size_t)info.st_size) {
		ssize_t got = read(fd, data + done, (size_t)info.st_size - done);

		if (got <= 0)
			fail("cannot read %s", path);
		done += (size_t)got;
	}
	data[done] = '\0';
	close(fd);
	*size = done;
	return data;
}

static unsigned long long number(const char *text)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno != 0 || *text == '\0' || *end != '\0')
		fail("bad number in the spec: %s", text);
	return value;
}

static void parse_spec(void)
{
	size_t size;
	char *data = read_file(SPEC_PATH, &size);
	char *words[8];
	char *cursor = data;
	char *limit = data + size;

#define NEXT(i)                                                          \
	do {                                                             \
		if (cursor >= limit)                                     \
			fail("the spec ends inside a record");          \
		words[i] = cursor;                                       \
		cursor += strlen(cursor) + 1;                            \
	} while (0)

	for (;;) {
		NEXT(0);
		if (strcmp(words[0], "end") == 0)
			break;
		if (strcmp(words[0], "program") == 0) {
			NEXT(1);
			program = words[1];
		} else if (strcmp(words[0], "arg") == 0) {
			NEXT(1);
			if (nargs >= MAX_ITEMS)
				fail("too many arguments");
			args[1 + nargs++] = words[1];
		} else if (strcmp(words[0], "env") == 0) {
			NEXT(1);
			if (nenvs >= MAX_ITEMS)
				fail("too many variables");
			envs[nenvs++] = words[1];
		} else if (strcmp(words[0], "cwd") == 0) {
			NEXT(1);
			cwd = words[1];
		} else if (strcmp(words[0], "hostname") == 0) {
			NEXT(1);
			hostname = words[1];
		} else if (strcmp(words[0], "port") == 0) {
			NEXT(1);
			port = (unsigned int)number(words[1]);
		} else if (strcmp(words[0], "id") == 0) {
			NEXT(1);
			NEXT(2);
			uid = (uid_t)number(words[1]);
			gid = (gid_t)number(words[2]);
		} else if (strcmp(words[0], "rlimit") == 0) {
			NEXT(1);
			NEXT(2);
			NEXT(3);
			if (nrlimits >= sizeof(rlimits) / sizeof(rlimits[0]))
				fail("too many resource limits");
			rlimits[nrlimits].resource = (int)number(words[1]);
			rlimits[nrlimits].value.rlim_cur = number(words[2]);
			rlimits[nrlimits].value.rlim_max = number(words[3]);
			nrlimits++;
		} else if (strcmp(words[0], "mount") == 0) {
			for (int i = 1; i <= 5; i++)
				NEXT(i);
			if (nmounts >= MAX_ITEMS)
				fail("too many mounts");
			mounts[nmounts].kind = words[1];
			mounts[nmounts].destination = words[2];
			mounts[nmounts].source = words[3];
			mounts[nmounts].flags = (unsigned long)number(words[4]);
			mounts[nmounts].data = *words[5] ? words[5] : NULL;
			nmounts++;
		} else if (strcmp(words[0], "output") == 0) {
			NEXT(1);
			NEXT(2);
			if (noutputs >= MAX_ITEMS)
				fail("too many outputs");
			outputs[noutputs].name = words[1];
			outputs[noutputs].path = words[2];
			noutputs++;
		} else {
			fail("unknown record in the spec: %s", words[0]);
		}
	}
#undef NEXT
	if (program == NULL)
		fail("the spec names no program");
	args[0] = program;
}

static void read_filter(void)
{
	size_t size;
	char *data = read_file(FILTER_PATH, &size);

	if (size == 0 || size % sizeof(struct sock_filter) != 0)
		fail("the seccomp filter has a bad size");
	filter.len = (unsigned short)(size / sizeof(struct sock_filter));
	filter.filter = (struct sock_filter *)data;
}

static void connect_host(void)
{
	struct sockaddr_vm address = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_HOST,
		.svm_port = port,
	};

	for (int attempt = 0; attempt < 50; attempt++) {
		host = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (host >= 0 && connect(host, (struct sockaddr *)&address, sizeof(address)) == 0) {
			send_line("ready\n");
			return;
		}
		if (host >= 0)
			close(host);
		host = -1;
		usleep(100000);
	}
	fail("cannot connect to the host over vsock port %u: %s", port, strerror(errno));
}

static void make_dirs(const char *path, mode_t mode)
{
	char buffer[4096];
	size_t length = strlen(path);

	if (length >= sizeof(buffer))
		fail("path too long: %s", path);
	memcpy(buffer, path, length + 1);
	for (char *c = buffer + 1; *c; c++) {
		if (*c != '/')
			continue;
		*c = '\0';
		if (mkdir(buffer, mode) < 0 && errno != EEXIST)
			fail("cannot create %s: %s", buffer, strerror(errno));
		*c = '/';
	}
	if (mkdir(buffer, mode) < 0 && errno != EEXIST)
		fail("cannot create %s: %s", buffer, strerror(errno));
}

static void make_parent(const char *path)
{
	char buffer[4096];
	char *slash;

	snprintf(buffer, sizeof(buffer), "%s", path);
	slash = strrchr(buffer, '/');
	if (slash != NULL && slash != buffer) {
		*slash = '\0';
		make_dirs(buffer, 0755);
	}
}

static void target_of(const struct mount_entry *entry, char *target, size_t size)
{
	if ((size_t)snprintf(target, size, ROOT "%s", entry->destination) >= size)
		fail("path too long: %s", entry->destination);
}

static void apply_mount(const struct mount_entry *entry)
{
	char target[4096];
	struct stat info;

	target_of(entry, target, sizeof(target));
	if (strcmp(entry->kind, "tmpfs") == 0) {
		make_dirs(target, 0755);
		if (mount("tmpfs", target, "tmpfs", entry->flags, entry->data) < 0)
			fail("cannot mount a tmpfs at %s: %s", entry->destination, strerror(errno));
		return;
	}
	if (strcmp(entry->kind, "bind") != 0)
		fail("cannot apply a %s mount at %s", entry->kind, entry->destination);
	if (lstat(entry->source, &info) < 0)
		fail("cannot bind %s: %s", entry->source, strerror(errno));
	if (S_ISLNK(info.st_mode)) {
		char link[4096];
		ssize_t length = readlink(entry->source, link, sizeof(link) - 1);

		if (length < 0)
			fail("cannot read link %s: %s", entry->source, strerror(errno));
		link[length] = '\0';
		make_parent(target);
		if (symlink(link, target) < 0)
			fail("cannot create link %s: %s", entry->destination, strerror(errno));
		return;
	}
	if (S_ISDIR(info.st_mode)) {
		make_dirs(target, 0755);
	} else {
		int fd;

		make_parent(target);
		fd = open(target, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
		if (fd < 0)
			fail("cannot create %s: %s", entry->destination, strerror(errno));
		close(fd);
	}
	if (mount(entry->source, target, NULL, MS_BIND | MS_REC, NULL) < 0)
		fail("cannot bind %s: %s", entry->destination, strerror(errno));
	if (mount(NULL, target, NULL, MS_REMOUNT | MS_BIND | entry->flags, NULL) < 0)
		fail("cannot remount %s: %s", entry->destination, strerror(errno));
}

static int is_input(const char *device)
{
	unsigned char block[136];
	int fd = open(device, O_RDONLY | O_CLOEXEC);
	ssize_t got;

	if (fd < 0)
		return 0;
	got = pread(fd, block, sizeof(block), 1024);
	close(fd);
	if (got != (ssize_t)sizeof(block))
		return 0;
	/* The ext4 superblock: s_magic at 56, s_volume_name at 120. */
	return block[56] == 0x53 && block[57] == 0xef &&
	       strncmp((const char *)block + 120, INPUT_LABEL, 16) == 0;
}

static void find_devices(char *input, char *output, size_t size)
{
	for (int attempt = 0; attempt < 100; attempt++) {
		DIR *dir = opendir("/dev");
		struct dirent *entry;
		int found = 0;

		*input = *output = '\0';
		if (dir == NULL)
			fail("cannot list /dev: %s", strerror(errno));
		while ((entry = readdir(dir)) != NULL) {
			char path[16];

			if (strncmp(entry->d_name, "vd", 2) != 0 || strlen(entry->d_name) != 3)
				continue;
			snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
			found++;
			snprintf(is_input(path) ? input : output, size, "%s", path);
		}
		closedir(dir);
		if (found == 2 && *input && *output)
			return;
		if (found > 2)
			fail("expected two block devices, found %d", found);
		usleep(20000);
	}
	fail("cannot find the input and output block devices");
}

static void loopback_up(void)
{
	struct ifreq request;
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		fail("cannot open a socket: %s", strerror(errno));
	memset(&request, 0, sizeof(request));
	strcpy(request.ifr_name, "lo");
	if (ioctl(fd, SIOCGIFFLAGS, &request) < 0)
		fail("cannot read the flags of lo: %s", strerror(errno));
	request.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &request) < 0)
		fail("cannot bring lo up: %s", strerror(errno));
	close(fd);
}

static const char *const dev_links[][2] = {
	{"fd", "/proc/self/fd"},
	{"stdin", "/proc/self/fd/0"},
	{"stdout", "/proc/self/fd/1"},
	{"stderr", "/proc/self/fd/2"},
};

static void setup(void)
{
	char input[64], output[64];

	if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL) < 0 && errno != EBUSY)
		fail("cannot mount /dev: %s", strerror(errno));
	find_devices(input, output, sizeof(input));
	if (mount(input, INPUTS, "ext4", MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) < 0)
		fail("cannot mount the inputs: %s", strerror(errno));
	setenv("CLOCHE_OUTPUT_DEVICE", output, 1);
	if (mount("tmpfs", ROOT, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") < 0)
		fail("cannot mount the sandbox root: %s", strerror(errno));
	for (size_t i = 0; i < nmounts; i++)
		if (strcmp(mounts[i].kind, "proc") != 0)
			apply_mount(&mounts[i]);
	for (size_t i = 0; i < sizeof(dev_links) / sizeof(dev_links[0]); i++) {
		char path[256];

		snprintf(path, sizeof(path), ROOT "/dev/%s", dev_links[i][0]);
		if (symlink(dev_links[i][1], path) < 0)
			fail("cannot create %s: %s", path, strerror(errno));
	}
	loopback_up();
}

static void drop_capabilities(void)
{
	struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
	struct __user_cap_data_struct data[2];

	for (int cap = 0; cap < 64; cap++)
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL)
			fail("cannot drop capability %d: %s", cap, strerror(errno));
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
		fail("cannot clear the ambient capabilities: %s", strerror(errno));
	memset(data, 0, sizeof(data));
	if (syscall(SYS_capset, &header, data) < 0)
		fail("cannot drop capabilities: %s", strerror(errno));
}

/*
 * The program keeps uid 0 of the guest. Without capabilities it can still
 * write root-owned files under /proc, such as kernel/core_pattern or
 * sysrq-trigger, so these paths are read-only, as in OCI runtimes.
 */
static const char *const proc_read_only[] = {"bus", "fs", "irq", "sys", "sysrq-trigger"};

static void protect_proc(const char *target)
{
	for (size_t i = 0; i < sizeof(proc_read_only) / sizeof(proc_read_only[0]); i++) {
		char path[4096];

		if ((size_t)snprintf(path, sizeof(path), "%s/%s", target, proc_read_only[i]) >=
		    sizeof(path))
			fail("path too long: %s", target);
		if (access(path, F_OK) < 0)
			continue;
		if (mount(path, path, NULL, MS_BIND | MS_REC, NULL) < 0 ||
		    mount(NULL, path, NULL,
			  MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
			  NULL) < 0)
			fail("cannot make %s read-only: %s", path, strerror(errno));
	}
}

/* Runs in the child, as PID 1 of the program's PID namespace. */
static void become_program(void)
{
	int null;

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		fail("cannot make mounts private: %s", strerror(errno));
	for (size_t i = 0; i < nmounts; i++) {
		char target[4096];

		if (strcmp(mounts[i].kind, "proc") != 0)
			continue;
		target_of(&mounts[i], target, sizeof(target));
		make_dirs(target, 0755);
		if (mount("proc", target, "proc", mounts[i].flags, mounts[i].data) < 0)
			fail("cannot mount proc at %s: %s", mounts[i].destination, strerror(errno));
		protect_proc(target);
	}
	if (sethostname(hostname, strlen(hostname)) < 0)
		fail("cannot set the host name: %s", strerror(errno));
	if (setdomainname("(none)", 6) < 0)
		fail("cannot set the domain name: %s", strerror(errno));
	if (chdir(ROOT) < 0 || mount(".", "/", NULL, MS_MOVE, NULL) < 0 || chroot(".") < 0)
		fail("cannot enter the sandbox root: %s", strerror(errno));
	if (chdir(cwd) < 0)
		fail("cannot change to %s: %s", cwd, strerror(errno));
	umask(022);
	null = open("/dev/null", O_RDONLY);
	if (null < 0 || dup2(null, 0) < 0)
		fail("cannot open /dev/null: %s", strerror(errno));
	if (null != 0)
		close(null);
	for (size_t i = 0; i < nrlimits; i++)
		if (setrlimit(rlimits[i].resource, &rlimits[i].value) < 0)
			fail("cannot set resource limit %d: %s", rlimits[i].resource, strerror(errno));
	if (setgroups(0, NULL) < 0 || setresgid(gid, gid, gid) < 0 || setresuid(uid, uid, uid) < 0)
		fail("cannot set the user and group: %s", strerror(errno));
	drop_capabilities();
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		fail("cannot set no_new_privs: %s", strerror(errno));
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter, 0, 0) < 0)
		fail("cannot install the seccomp filter: %s", strerror(errno));
	envs[nenvs] = NULL;
	args[nargs + 1] = NULL;
	execve(program, (char *const *)args, (char *const *)envs);
	fail("cannot run %s: %s", program, strerror(errno));
}

/* The output archive. */

static int archive = -1;
static char buffer[BUFFER_SIZE];
static size_t buffered;
static unsigned long long offset;
static unsigned long inode;
static const char *walk_name;
static size_t walk_base;

static void flush_buffer(void)
{
	size_t done = 0;

	while (done < buffered) {
		ssize_t written = write(archive, buffer + done, buffered - done);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			fail("cannot write the outputs: %s", strerror(errno));
		}
		done += (size_t)written;
	}
	buffered = 0;
}

static void emit(const void *data, size_t length)
{
	const char *bytes = data;

	offset += length;
	while (length > 0) {
		size_t room = sizeof(buffer) - buffered;
		size_t part = length < room ? length : room;

		memcpy(buffer + buffered, bytes, part);
		buffered += part;
		bytes += part;
		length -= part;
		if (buffered == sizeof(buffer))
			flush_buffer();
	}
}

static void pad(void)
{
	static const char zeros[4];

	emit(zeros, (4 - offset % 4) % 4);
}

static void header(const char *name, mode_t mode, unsigned long long size, dev_t rdev)
{
	char text[128];

	if (size > 0xffffffffULL)
		fail("output file %s is larger than 4 GiB", name);
	snprintf(text, sizeof(text),
		 "070701%08lX%08X%08X%08X%08X%08X%08llX%08X%08X%08X%08X%08zX%08X",
		 ++inode, (unsigned int)mode, 0u, 0u, 1u, 0u, size, 0u, 0u, major(rdev),
		 minor(rdev), strlen(name) + 1, 0u);
	emit(text, 110);
	emit(name, strlen(name) + 1);
	pad();
}

static int add_entry(const char *path, const struct stat *info, int kind, struct FTW *where)
{
	char name[8192];

	(void)where;
	if (kind == FTW_NS || kind == FTW_DNR)
		fail("cannot read output %s: %s", path, strerror(errno));
	if ((size_t)snprintf(name, sizeof(name), "%s%s", walk_name, path + walk_base) >= sizeof(name))
		fail("output path too long: %s", path);
	if (S_ISREG(info->st_mode)) {
		int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		unsigned long long left = (unsigned long long)info->st_size;

		if (fd < 0)
			fail("cannot open output %s: %s", path, strerror(errno));
		header(name, info->st_mode, left, 0);
		while (left > 0) {
			char chunk[BUFFER_SIZE];
			ssize_t got = read(fd, chunk, left < sizeof(chunk) ? left : sizeof(chunk));

			if (got <= 0)
				fail("cannot read output %s", path);
			emit(chunk, (size_t)got);
			left -= (unsigned long long)got;
		}
		close(fd);
		pad();
	} else if (S_ISLNK(info->st_mode)) {
		char link[4096];
		ssize_t length = readlink(path, link, sizeof(link));

		if (length < 0)
			fail("cannot read link %s: %s", path, strerror(errno));
		header(name, info->st_mode, (unsigned long long)length, 0);
		emit(link, (size_t)length);
		pad();
	} else {
		/* Directories, and anything else for the host to refuse. */
		header(name, info->st_mode, 0, info->st_rdev);
	}
	return 0;
}

static void write_outputs(void)
{
	const char *device = getenv("CLOCHE_OUTPUT_DEVICE");

	archive = open(device, O_WRONLY | O_CLOEXEC);
	if (archive < 0)
		fail("cannot open the output device: %s", strerror(errno));
	for (size_t i = 0; i < noutputs; i++) {
		char path[4096];
		struct stat info;

		snprintf(path, sizeof(path), ROOT "%s", outputs[i].path);
		if (lstat(path, &info) < 0)
			continue;
		walk_name = outputs[i].name;
		walk_base = strlen(path);
		if (nftw(path, add_entry, 64, FTW_PHYS | FTW_MOUNT) != 0)
			fail("cannot walk output %s: %s", outputs[i].name, strerror(errno));
	}
	header("TRAILER!!!", 0, 0, 0);
	flush_buffer();
	if (fsync(archive) < 0 || close(archive) < 0)
		fail("cannot flush the outputs: %s", strerror(errno));
}

int main(void)
{
	int error_pipe[2];
	char message[4096];
	ssize_t got;
	size_t length = 0;
	int status;
	pid_t child;

	if (getpid() != 1)
		fail("the guest init must run as PID 1");
	parse_spec();
	read_filter();
	connect_host();
	setup();
	if (pipe2(error_pipe, O_CLOEXEC) < 0)
		fail("cannot create a pipe: %s", strerror(errno));
	child = (pid_t)syscall(SYS_clone, CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC |
					      SIGCHLD,
			       0, 0, 0, 0);
	if (child < 0)
		fail("cannot start the program: %s", strerror(errno));
	if (child == 0) {
		close(error_pipe[0]);
		close(host);
		host = -1;
		child_errors = error_pipe[1];
		become_program();
	}
	close(error_pipe[1]);
	while ((got = read(error_pipe[0], message + length, sizeof(message) - 1 - length)) > 0)
		length += (size_t)got;
	close(error_pipe[0]);
	message[length] = '\0';
	while (waitpid(child, &status, 0) < 0)
		if (errno != EINTR)
			fail("cannot wait for the program: %s", strerror(errno));
	if (length > 0)
		fail("sandbox setup failed: %s", message);
	if (WIFSIGNALED(status)) {
		snprintf(message, sizeof(message), "killed %d\n", WTERMSIG(status));
	} else if (WEXITSTATUS(status) != 0) {
		snprintf(message, sizeof(message), "exited %d\n", WEXITSTATUS(status));
	} else {
		write_outputs();
		snprintf(message, sizeof(message), "exited 0\n");
	}
	send_line(message);
	power_off();
}
