/* translog_server
	  by james@ustc.edu.cn 2018.06.04
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <pwd.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/md5.h>

#define MAXLEN 		16384
#define MAXLINE 	1024*1024

int daemon_proc;		/* set nonzero by daemon_init() */
int debug = 0;

int my_port;
char config_file[MAXLEN];
char work_user[MAXLEN];
int work_uid;
size_t total_file_len, upload_file_len;

char *get_file_md5sum(char *file_name)
{
	int n;
	MD5_CTX c;
	char buf[512];
	ssize_t bytes;
	FILE *fp;

	unsigned char out[MD5_DIGEST_LENGTH];
	static char outhex[64];

	MD5_Init(&c);
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		outhex[0] = 0;
		return (char *)outhex;
	}

	bytes = fread(buf, 1, 512, fp);

	while (bytes > 0) {
		MD5_Update(&c, buf, bytes);
		bytes = fread(buf, 1, 512, fp);
	}

	MD5_Final(out, &c);
	fclose(fp);
	outhex[0] = 0;
	for (n = 0; n < MD5_DIGEST_LENGTH; n++) {
		snprintf(outhex + n * 2, 3, "%02x", out[n]);
	}

	if (debug)
		fprintf(stderr, "md5sum of file %s is %s\n", file_name, outhex);

	return (outhex);
}

void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLEN];

	errno_save = errno;	/* value caller might want printed */
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* this is safe */
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
	strcat(buf, "\n");

	if (daemon_proc) {
		syslog(level, "%s", buf);
	} else {
		fflush(stdout);	/* in case stdout and stderr are the same */
		fputs(buf, stderr);
		fflush(stderr);
	}
	return;
}

void err_msg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_INFO, fmt, ap);
	va_end(ap);
	return;
}

void Debug(const char *fmt, ...)
{
	va_list ap;
	if (debug) {
		va_start(ap, fmt);
		err_doit(0, LOG_INFO, fmt, ap);
		va_end(ap);
	}
	return;
}

void err_quit(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void err_sys(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void daemon_init(const char *pname, int facility)
{
	int i;
	pid_t pid;
	if ((pid = fork()) != 0)
		exit(0);	/* parent terminates */

	/* 41st child continues */
	setsid();		/* become session leader */

	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	if ((pid = fork()) != 0)
		exit(0);	/* 1st child terminates */

	/* 42nd child continues */
	daemon_proc = 1;	/* for our err_XXX() functions */

	umask(0);		/* clear our file mode creation mask */

	for (i = 0; i < 10; i++)
		close(i);

	openlog(pname, LOG_PID, facility);
}

ssize_t				/* Read "n" bytes from a descriptor. */
readn(int fd, void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nread;
	char *ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ((nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;	/* and call read() again */
			else
				return (-1);
		} else if (nread == 0)
			break;	/* EOF */

		nleft -= nread;
		ptr += nread;
	}
	return (n - nleft);	/* return >= 0 */
}

/* end readn */

ssize_t Readn(int fd, void *ptr, size_t nbytes)
{
	ssize_t n;

	if ((n = readn(fd, ptr, nbytes)) < 0)
		err_sys("readn error");
	return (n);
}

ssize_t readline(int fd, void *vptr, size_t maxlen)
{
	int n, rc;
	char c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++) {
		if ((rc = readn(fd, &c, 1)) == 1) {
			*ptr++ = c;
			if (c == '\n')
				break;	/* newline is stored, like fgets() */
		} else if (rc == 0) {
			if (n == 1)
				return (0);	/* EOF, no data read */
			else
				break;	/* EOF, some data was read */
		} else
			return (-1);	/* error, errno set by read() */
	}

	*ptr = 0;		/* null terminate like fgets() */
	return (n);
}

ssize_t Readline(int fd, void *ptr, size_t maxlen)
{
	ssize_t n;

	if ((n = readline(fd, ptr, maxlen)) < 0)
		err_sys("readline error");
	return (n);
}

/* include writen */
ssize_t				/* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nwritten;
	const char *ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ((nwritten = write(fd, ptr, nleft)) <= 0) {
			if (errno == EINTR)
				nwritten = 0;	/* and call write() again */
			else
				return (-1);	/* error */
		}

		nleft -= nwritten;
		ptr += nwritten;
	}
	return (n);
}

/* end writen */

void Writen(int fd, void *ptr, size_t nbytes)
{
	if (writen(fd, ptr, nbytes) != nbytes)
		err_sys("writen error");
}

char *stamp(void)
{
	static char st_buf[200];
	struct timeval tv;
	struct timezone tz;
	struct tm *tm;

	gettimeofday(&tv, &tz);
	tm = localtime(&tv.tv_sec);

	snprintf(st_buf, 200, "%02d%02d %02d:%02d:%02d.%06ld", tm->tm_mon + 1, tm->tm_mday,
		 tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
	return st_buf;
}

void set_socket_keepalive(int fd)
{
	int keepalive = 1;	// 开启keepalive属性
	int keepidle = 5;	// 如该连接在60秒内没有任何数据往来,则进行探测
	int keepinterval = 5;	// 探测时发包的时间间隔为5 秒
	int keepcount = 3;	// 探测尝试的次数。如果第1次探测包就收到响应了,则后2次的不再发
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
	setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (void *)&keepidle, sizeof(keepidle));
	setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval, sizeof(keepinterval));
	setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount, sizeof(keepcount));
}

int bind_and_listen(void)
{
	int listenfd;
	int enable = 1;
	int ipv6 = 0;

	if (ipv6)
		listenfd = socket(AF_INET6, SOCK_STREAM, 0);
	else
		listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		perror("error: socket");
		exit(-1);
	}
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("error: setsockopt(SO_REUSEADDR)");
		exit(-1);
	}
	if (setsockopt(listenfd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(int)) < 0) {
		perror("Couldn't setsockopt(TCP_NODELAY)\n");
		exit(-1);
	}
	if (ipv6) {
		static struct sockaddr_in6 serv_addr6;
		memset(&serv_addr6, 0, sizeof(serv_addr6));
		serv_addr6.sin6_family = AF_INET6;
		serv_addr6.sin6_port = htons(my_port);
		if (bind(listenfd, (struct sockaddr *)&serv_addr6, sizeof(serv_addr6)) < 0) {
			perror("error: bind");
			exit(-1);
		}
	} else {
		static struct sockaddr_in serv_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(my_port);
		if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
			perror("error: bind");
			exit(-1);
		}
	}
	if (listen(listenfd, 64) < 0) {
		perror("error: listen");
		exit(-1);
	}
	return listenfd;
}

unsigned char x2c(char x)
{
	if (isdigit(x))
		return x - '0';
	else if (islower(x))
		return x - 'a' + 10;
	else
		return x - 'A' + 10;
}

int ishex(char c)
{
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
		return 1;
	else
		return 0;

}

char *url_decode(char *s)
{
	char *p = s, *str = s;
	while (*s) {
		if (*s == '+')
			*p = ' ';
		else if ((*s == '%') && ishex(*(s + 1)) && ishex(*(s + 2))) {
			*p = (x2c(*(s + 1)) << 4) + x2c(*(s + 2));
			s += 2;
		} else
			*p = *s;
		s++;
		p++;
	}
	*p = 0;
	return str;
}

char *get_hashed_file_name(char *md5sum, size_t file_len)
{
	static char hashed_file_name[MAXLEN];
	snprintf(hashed_file_name, MAXLEN, "/hashed_file/%c%c/%c%c/%s_%zu",
		 md5sum[0], md5sum[1], md5sum[2], md5sum[3], md5sum, file_len);
	return hashed_file_name;
}

void create_dir(char *dir_name)
{
	char str[MAXLEN];
	int i, len;
	strncpy(str, dir_name, MAXLEN);
	len = strlen(str);
	for (i = 0; i < len; i++) {
		if ((str[i] == '/') && (i != 0)) {
			str[i] = '\0';
			if (access(str, 0) != 0) {
				if (debug)
					fprintf(stderr, "mkdir %s\n", str);
				mkdir(str, 0755);
			}
			str[i] = '/';
		}
	}
	if (len > 0 && access(str, 0) != 0) {
		if (debug)
			fprintf(stderr, " mkdir %s\n", str);
		mkdir(str, 0755);
	}
}

void check_and_create_dir(char *file_name)
{
	if (strchr(file_name, '/')) {	// file_name has directory, check and mkdir 
		char str[MAXLEN];
		int i, len;
		strncpy(str, file_name, MAXLEN);
		len = strlen(str);
		// find the last '/'
		for (i = len - 1; i >= 0; i--)
			if (str[i] == '/') {
				str[i] = 0;
				break;
			}
		create_dir(str);
	}
}

void RecvHashedFile(int fd, char *md5sum, char *hashed_file_name, size_t file_len)
{
	char buf[MAXLEN];
	char file_name[MAXLEN];
	size_t file_got = 0;
	int n;

	strcpy(buf, "DATA I need your data\n");
	Writen(fd, buf, strlen(buf));
	snprintf(file_name, MAXLEN, "/hashed_file/tmp.%d", getpid());
	check_and_create_dir(file_name);
	FILE *fp = fopen(file_name, "w");
	if (fp == NULL) {
		snprintf(buf, MAXLEN, "ERROR open tmpfile %s for write\n", file_name);
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
		exit(-1);
	}
	if (debug)
		fprintf(stderr, "tmpfile %s open for write\n", file_name);
	while (1) {
		size_t remains = file_len - file_got;
		char buf[MAXLINE];
		if (remains == 0)
			break;
		if (remains >= MAXLINE)
			n = Readn(fd, buf, MAXLINE);
		else
			n = Readn(fd, buf, remains);
		file_got += n;
		upload_file_len += n;
		if (n == 0) {	// end of file
			fclose(fp);
			unlink(file_name);
			snprintf(buf, 100, "ERROR file length %zu\n", file_got);
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "%s", buf);
			exit(-1);
		}
		if (fwrite(buf, 1, n, fp) != n) {
			fclose(fp);
			unlink(file_name);
			strcpy(buf, "ERROR file write\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "%s", buf);
			exit(-1);
		}
		if (debug)
			fprintf(stderr, "write %zu of %zu\n", file_got, file_len);
	}
	fclose(fp);
	fprintf(stderr, "md5sum :%s:\n", md5sum);
	fprintf(stderr, "md5sum :%s:(new_file)\n", get_file_md5sum(file_name));
	if (memcmp(md5sum, get_file_md5sum(file_name), 32) != 0) {
		unlink(file_name);
		strcpy(buf, "ERROR file md5sum\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
		exit(-1);
	}
	check_and_create_dir(hashed_file_name);
	n = rename(file_name, hashed_file_name);
	if (n == 0)
		return;

	unlink(file_name);
	snprintf(buf, 100, "ERROR rename uploaded file error %d, exit\n", errno);
	Writen(fd, buf, strlen(buf));
	if (debug)
		fprintf(stderr, "ERROR link file error %d, exit\n", errno);
	exit(-1);
}

void ProcessFile(int fd)
{
	char buf[MAXLEN];
	char file_name[MAXLEN];
	char hashed_file[MAXLEN];
	char md5sum[MAXLEN];
	char *p;
	size_t file_len;
	int n;

	n = Readline(fd, buf, MAXLEN);
	buf[n] = 0;
	if (n == 0) {
		if (debug)
			fprintf(stderr, "read 0, exit\n");
		exit(0);
	}

	if (memcmp(buf, "END\n", 4) == 0) {	// END all
		snprintf(buf, MAXLEN, "BYE %zu of %zu\n", upload_file_len, total_file_len);
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
		exit(0);
	}

	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;

	if (memcmp(buf, "MKDIR ", 6) == 0) {	// MKDIR dir_name
		char str[MAXLEN];
		p = buf + 6;
		url_decode(p);
		snprintf(str, MAXLEN, "/data/%s", p);
		create_dir(str);
		snprintf(buf, 100, "OK mkdir\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "OK mkdir\n");
		return;
	}

	if (memcmp(buf, "MKLINK ", 7) == 0) {	// MKLINK file_name linkto_name
		char strnew[MAXLEN], strold[MAXLEN];
		p = buf + 7;
		while (*p && (*p != ' '))
			p++;
		if (*p == 0) {	// 
			if (debug)
				fprintf(stderr, "%s error\n", buf);
			exit(-1);
		}
		*p = 0;
		p++;
		url_decode(buf + 7);
		snprintf(strnew, MAXLEN, "/data/%s", buf + 7);
		url_decode(p);
		snprintf(strold, MAXLEN, "%s", p);
		check_and_create_dir(strnew);
		if (symlink(strold, strnew) == 0) {
			snprintf(buf, 100, "OK mklink\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "OK mklink\n");
		} else {
			snprintf(buf, 100, "ERROR mklink\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "ERROR mklink\n");
		}
		return;
	}
// C -> FILE md5sum file_len file_name\n
//
	if (memcmp(buf, "FILE ", 5) != 0) {	// FILE md5sum file_len file_name
		if (debug)
			fprintf(stderr, "%s unknown cmd\n", buf);
		exit(-1);
	}
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;
	p = buf + 5;
	while (*p && (*p != ' '))
		p++;
	if (*p == 0) {		// no file_len 
		if (debug)
			fprintf(stderr, "%s error\n", buf);
		exit(-1);
	}
	*p = 0;
	p++;
	if (strlen(buf + 5) != 32) {	// md5sum len
		p--;
		*p = ' ';
		if (debug)
			fprintf(stderr, "%s md5sum len error\n", buf);
		exit(-1);
	}
	strcpy(md5sum, buf + 5);
	if (sscanf(p, "%zu", &file_len) != 1) {
		p--;
		*p = ' ';
		if (debug)
			fprintf(stderr, "%s file len error\n", buf);
		exit(-1);
	}
	total_file_len += file_len;
	while (*p && (*p != ' '))
		p++;
	if (*p == 0) {		// no file name
		if (debug)
			fprintf(stderr, "no file name\n");
		exit(-1);
	}
	p++;
	if (*p == 0) {		// no file name
		if (debug)
			fprintf(stderr, "no file name\n");
		exit(-1);
	}
	while (*p && *p == '/')
		p++;
	if (*p == 0) {		// no file name
		if (debug)
			fprintf(stderr, "no file name\n");
		exit(-1);
	}
	url_decode(p);
	snprintf(file_name, MAXLEN, "/data/%s", p);
	if (debug)
		fprintf(stderr, "C->S: FILE %s %zu %s\n", md5sum, file_len, file_name);

	if (access(file_name, F_OK) != -1) {	// file exists
		strcpy(buf, "ERROR file exist\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "file %s exist, return\n", file_name);
		return;
	}
	strcpy(hashed_file, get_hashed_file_name(md5sum, file_len));
	if (access(hashed_file, F_OK) != 0)	// hashed file not exist, recv it
		RecvHashedFile(fd, md5sum, hashed_file, file_len);

	check_and_create_dir(file_name);

	n = link(hashed_file, file_name);
	if (n == 0) {		// OK
		snprintf(buf, 100, "OK file in server\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "OK file in server\n");
		return;
	}

	snprintf(buf, 100, "ERROR link file error %d\n", errno);
	Writen(fd, buf, strlen(buf));
	if (debug)
		fprintf(stderr, "ERROR link file error %d\n", errno);
}

void Process(int fd)
{
	char buf[MAXLEN];
	char *p;
	int n;
	int pass_ok;

//      password check
// C -> PASS pasword
// S    open config_file.txt read password and work_dir, chroot(work_dir), setuid(work_uid)
//      
	while (1) {		// PASS password check
		FILE *fp;
		char file_buf[MAXLEN];
		pass_ok = 0;
		n = Readline(fd, buf, MAXLEN);
		buf[n] = 0;
		if (n == 0)
			exit(0);
		if (memcmp(buf, "PASS ", 5) != 0)
			continue;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		if (strlen(buf + 5) == 0)
			continue;
		fp = fopen(config_file, "r");
		if (fp == NULL) {
			strcpy(buf, "ERROR open config file\n");
			Writen(fd, buf, strlen(buf));
			exit(-1);
		}
		while (fgets(file_buf, MAXLEN, fp)) {
			if (file_buf[0] == '#')
				continue;
			if (file_buf[strlen(file_buf) - 1] == '\n')
				file_buf[strlen(file_buf) - 1] = 0;
			p = file_buf;
			while (*p && (*p != ' '))
				p++;
			if (*p == 0)
				continue;
			*p = 0;
			p++;
			if (strcmp(buf + 5, file_buf) == 0) {
				pass_ok = 1;
				while (*p && (*p == ' '))
					p++;

				if (debug)
					fprintf(stderr, "password ok, work_dir is %s\n", p);
				if (chroot(p) != 0) {
					perror("chroot");
					snprintf(buf, MAXLEN, "ERROR chroot to %s\n", p);
					Writen(fd, buf, strlen(buf));
					exit(-1);
				}
				setuid(work_uid);
				chdir("/");
				break;
			}
		}
		fclose(fp);
		if (pass_ok)
			break;
		strcpy(buf, "ERROR password\n");
		Writen(fd, buf, strlen(buf));
	}
	strcpy(buf, "OK password ok\n");
	Writen(fd, buf, strlen(buf));

	while (1)
		ProcessFile(fd);
}

void usage(void)
{
	printf("Usage:\n");
	printf("./translog_server options\n");
	printf(" options:\n");
	printf("    -p port\n");
	printf("    -f config_file\n");
	printf("    -u user_name    change to user before write file\n");
	printf("\n");
	printf("    -d              enable debug\n");
	printf("\n");
	printf("config_file:\n");
	printf("password work_dir\n");
	printf("...\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int c;
	int listenfd;
	struct passwd *pw;
	if (argc < 7)
		usage();

	while ((c = getopt(argc, argv, "p:f:u:d")) != EOF)
		switch (c) {
		case 'p':
			my_port = atoi(optarg);;
			break;
		case 'f':
			strncpy(config_file, optarg, MAXLEN - 1);
			break;
		case 'u':
			strncpy(work_user, optarg, MAXLEN - 1);
			pw = getpwnam(work_user);
			if (pw)
				work_uid = pw->pw_uid;
			else {
				fprintf(stderr, "user %s not found\n", work_user);
				exit(-1);
			}
			break;
		case 'd':
			debug = 1;
			break;
		}

	if ((my_port == 0) || (config_file[0] == 0) || (work_user[0] == 0))
		usage();
	if (debug) {
		printf("         debug = 1\n");
		printf("          port = %d\n", my_port);
		printf("     work user = %s\n", work_user);
		printf("      work uid = %d\n", work_uid);
		printf("   config_file = %s\n", config_file);
		printf("\n");
	}

	signal(SIGCHLD, SIG_IGN);
	if (debug == 0) {
		daemon_init("translog_server", LOG_DAEMON);
		while (1) {
			int pid;
			pid = fork();
			if (pid == 0)	// child do the job
				break;
			else if (pid == -1)	// error
				exit(0);
			else
				wait(NULL);	// parent wait for child
			sleep(2);	// wait 2 second, and rerun
		}
	}

	listenfd = bind_and_listen();
	while (1) {
		int infd;
		int pid;
		infd = accept(listenfd, NULL, 0);
		if (infd < 0)
			continue;
		pid = fork();
		if (pid == 0)
			Process(infd);
		close(infd);
	}

	return 0;
}
