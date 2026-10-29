/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The program run by test_run.py. argv[1] selects what it does;
 * each check prints "name=errno", with 0 for success.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void check(const char *name, long rc)
{
	printf("%s=%d\n", name, rc < 0 ? errno : 0);
}

static const char *in_out(const char *name)
{
	static char path[4096];

	snprintf(path, sizeof(path), "%s/%s", getenv("out"), name);
	return path;
}

static void make_out(void)
{
	FILE *file;

	mkdir(getenv("out"), 0755);
	file = fopen(in_out("file"), "w");
	fputs("data\n", file);
	fclose(file);
}

static int udp_connect(const char *address)
{
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(53) };
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	inet_pton(AF_INET, address, &to.sin_addr);
	return connect(sock, (struct sockaddr *)&to, sizeof(to));
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";
	char text[4096];
	mode_t mask;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!strcmp(mode, "env")) {
		for (char **e = environ; *e; e++)
			printf("env:%s\n", *e);
		gethostname(text, sizeof(text));
		printf("hostname=%s\npid=%d\nuid=%d\n", text, getpid(), getuid());
		printf("cwd=%s\n", getcwd(text, sizeof(text)));
		mask = umask(0);
		umask(mask);
		printf("umask=%o\n", mask);
		for (int i = 2; i < argc; i++)
			printf("arg=%s\n", argv[i]);
		make_out();
	} else if (!strcmp(mode, "isolation")) {
		snprintf(text, sizeof(text), "%s/new", argv[2]);
		check("etc", access("/etc/passwd", F_OK));
		check("route", udp_connect("192.0.2.1"));
		check("loopback", udp_connect("127.0.0.1"));
		check("write_input", open(text, O_CREAT | O_WRONLY, 0644));
		check("umount_input", umount2(argv[2], MNT_DETACH));
		check("remount_input", mount(NULL, argv[2], NULL, MS_REMOUNT | MS_BIND, NULL));
		check("mount", mount("none", "/build", "tmpfs", 0, NULL));
		check("null", open("/dev/null", O_WRONLY));
		check("shm", open("/dev/shm/x", O_CREAT | O_WRONLY, 0600));
		check("core_pattern", open("/proc/sys/kernel/core_pattern", O_WRONLY));
		check("sysrq", open("/proc/sysrq-trigger", O_WRONLY));
		make_out();
	} else if (!strcmp(mode, "harden")) {
		make_out();
		check("chmod_setuid", chmod(in_out("file"), 04755));
		check("chmod_setgid", chmod(in_out("file"), 02755));
		check("chmod_plain", chmod(in_out("file"), 0700));
		check("setxattr", setxattr(in_out("file"), "user.x", "1", 1, 0));
		check("keyctl", syscall(SYS_keyctl, 0, 0, 0, 0, 0));
		check("io_uring", syscall(425, 1, NULL));
		check("create_setuid", open(in_out("suid"), O_CREAT | O_WRONLY, 06755));
	} else if (!strcmp(mode, "fail")) {
		puts("failing on purpose");
		return 2;
	} else if (!strcmp(mode, "escape")) {
		symlink("/etc/passwd", getenv("out"));
	} else if (!strcmp(mode, "fifo")) {
		mkdir(getenv("out"), 0755);
		mkfifo(in_out("pipe"), 0644);
	} else if (!strcmp(mode, "open")) {
		make_out();
		check("open", open(argv[2], O_RDONLY));
	} else if (!strcmp(mode, "refer")) {
		FILE *file;

		make_out();
		file = fopen(in_out("refs"), "w");
		for (int i = 2; i < argc; i++)
			fprintf(file, "%s\n", argv[i]);
		fclose(file);
	} else if (!strcmp(mode, "clock")) {
		struct timespec now;
		FILE *file;

		make_out();
		clock_gettime(CLOCK_REALTIME, &now);
		file = fopen(in_out("clock"), "w");
		fprintf(file, "%ld.%09ld\n", (long)now.tv_sec, now.tv_nsec);
		fclose(file);
	} else if (!strcmp(mode, "sleep")) {
		puts("sleeping");
		sleep(30);
	}
	return 0;
}
