/* hbackup_server
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

#include "util.c"

int my_port;
int ipv6 = 0;
char config_file[MAXLEN];
char work_user[MAXLEN];
int work_uid;
size_t total_file_len, upload_file_len;
size_t total_files, total_dirs, total_links;

int bind_and_listen(void)
{
	int listenfd;
	int enable = 1;

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

// return 1 OK
// return 0 error

int RecvHashedFile(int fd, char *md5sum, char *hashed_file_name, size_t file_len)
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
		const char format[] = "ERROR open tmpfile %.*s for write, exit\n";
		snprintf(buf, MAXLEN, format, (int)(MAXLEN - sizeof(format)), file_name);
		Writen(fd, buf, strlen(buf));
		if (debug)
			printf("%s", buf);
		exit(-1);
	}
	if (debug)
		printf("open tmpfile %s for write\n", file_name);
	while (1) {
		char buf[MAXLINE];
		size_t remains = file_len - file_got;
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
			snprintf(buf, 100, "ERROR file length %zu, but only read %zu, exit\n",
				 file_len, file_got);
			Writen(fd, buf, strlen(buf));
			if (debug)
				printf("%s", buf);
			exit(-1);
		}
		if (fwrite(buf, 1, n, fp) != n) {
			fclose(fp);
			unlink(file_name);
			strcpy(buf, "ERROR file write\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				printf("%s", buf);
			exit(-1);
		}
		if (debug)
			printf("write %zu of %zu\n", file_got, file_len);
	}
	fclose(fp);
	if (memcmp(md5sum, get_file_md5sum(file_name), 32) != 0) {
		unlink(file_name);
		strcpy(buf,
		       "ERROR upload file md5sum error, maybe file changed during uploading\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			printf("%s", buf);
		return 0;
	}
	check_and_create_dir(hashed_file_name);
	n = rename(file_name, hashed_file_name);
	if (n == 0)
		return 1;

	unlink(file_name);
	snprintf(buf, 100, "ERROR rename uploaded file error %d, exit\n", errno);
	Writen(fd, buf, strlen(buf));
	if (debug)
		printf("%s", buf);
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
			printf("read 0, exit\n");
		exit(0);
	}

	if (memcmp(buf, "END\n", 4) == 0) {	// END all
		snprintf(buf, MAXLEN,
			 "BYE File/Dir/Link: %zu/%zu/%zu UploadBytes/TotalBytes: %zu/%zu\n",
			 total_files, total_dirs, total_links, upload_file_len, total_file_len);
		Writen(fd, buf, strlen(buf));
		if (debug)
			printf("%s", buf);
		exit(0);
	}

	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;

	if (memcmp(buf, "MKDIR ", 6) == 0) {	// MKDIR dir_name
		char str[MAXLEN];
		struct stat stbuf;
		total_dirs++;
		p = buf + 6;
		if (debug)
			printf("C->S %s ", buf);
		url_decode(p);
		snprintf(str, MAXLEN, "/data/%s", p);
		if (stat(str, &stbuf) == 0) {
			if (S_ISDIR(stbuf.st_mode)) {	// dir exists
				strcpy(buf, "OK mkdir, dir in server\n");
				Writen(fd, buf, strlen(buf));
				if (debug)
					printf("%s", buf);
				return;
			}
			strcpy(buf, "ERROR mkdir, name exists, exit\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				printf("%s", buf);
			exit(-1);
		}
		create_dir(str);
		strcpy(buf, "OK mkdir\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			printf("%s", buf);
		return;
	}

	if (memcmp(buf, "MKLINK ", 7) == 0) {	// MKLINK file_name linkto_name
		char strnew[MAXLEN], strold[MAXLEN];
		struct stat stbuf;
		total_links++;
		if (debug)
			printf("C->S %s ", buf);
		p = buf + 7;
		while (*p && (*p != ' '))
			p++;
		if (*p == 0) {	// 
			if (debug)
				printf("%s error\n", buf);
			exit(-1);
		}
		*p = 0;
		p++;
		url_decode(buf + 7);
		snprintf(strnew, MAXLEN, "/data/%s", buf + 7);
		url_decode(p);
		snprintf(strold, MAXLEN, "%s", p);
		if (lstat(strnew, &stbuf) == 0) {
			if (S_ISLNK(stbuf.st_mode)) {	// link exists
				strcpy(buf, "OK mklink, link in server\n");
				Writen(fd, buf, strlen(buf));
				if (debug)
					printf("%s", buf);
				return;
			}
			strcpy(buf, "ERROR mklink, name exists, exit\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				printf("%s", buf);
			exit(-1);
		}
		check_and_create_dir(strnew);
		if (symlink(strold, strnew) == 0) {
			strcpy(buf, "OK mklink\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				printf("%s", buf);
		} else {
			strcpy(buf, "ERROR mklink, exit\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				printf("%s", buf);
			exit(-1);
		}
		return;
	}
// C -> FILE md5sum file_len file_name\n
//
	if (memcmp(buf, "FILE ", 5) != 0) {	// FILE md5sum file_len file_name
		strcpy(buf, "ERROR unknow cmd, exit\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			printf("%s", buf);
		exit(-1);
	}
	total_files++;
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;
	p = buf + 5;
	while (*p && (*p != ' '))
		p++;
	if (*p == 0) {		// no file_len 
		if (debug)
			printf("%s error\n", buf);
		exit(-1);
	}
	*p = 0;
	p++;
	if (strlen(buf + 5) != 32) {	// md5sum len
		p--;
		*p = ' ';
		if (debug)
			printf("%s md5sum len error, exit\n", buf);
		exit(-1);
	}
	strcpy(md5sum, buf + 5);
	if (sscanf(p, "%zu", &file_len) != 1) {
		p--;
		*p = ' ';
		if (debug)
			printf("%s file len error, exit\n", buf);
		exit(-1);
	}
	total_file_len += file_len;
	while (*p && (*p != ' '))
		p++;
	if (*p == 0) {		// no file name
		if (debug)
			printf("no file name, exit\n");
		exit(-1);
	}
	p++;
	if (*p == 0) {		// no file name
		if (debug)
			printf("no file name, exit\n");
		exit(-1);
	}
	while (*p && *p == '/')
		p++;
	if (*p == 0) {		// no file name
		if (debug)
			printf("no file name, exit\n");
		exit(-1);
	}
	url_decode(p);
	snprintf(file_name, MAXLEN, "/data/%s", p);
	if (debug)
		printf("C->S FILE %s %zu %s ", md5sum, file_len, file_name);

	struct stat stbuf;
	strcpy(hashed_file, get_hashed_file_name(md5sum, file_len));
	if (lstat(file_name, &stbuf) == 0) {	// file exists, check if the same, I use lstat, not stat, right?
		struct stat stbuf_hashed;
		if (lstat(hashed_file, &stbuf_hashed) == 0) {	// get hashed file stat
			if (stbuf.st_ino == stbuf_hashed.st_ino)	// the same file
				strcpy(buf, "OK same file in server\n");
			else
				strcpy(buf,
				       "ERROR file exists, but not the same md5sum, maybe you are overwrite file\n");
		} else
			strcpy(buf,
			       "ERROR file exists, hashed file not exists, maybe you are overwirting file\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			printf("%s", buf);
		return;
	}
	if (access(hashed_file, F_OK) != 0)	// hashed file not exists, recv it
		if (RecvHashedFile(fd, md5sum, hashed_file, file_len) == 0)
			return;

	check_and_create_dir(file_name);

	n = link(hashed_file, file_name);
	if (n == 0) {		// OK
		strcpy(buf, "OK file in server\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			printf("%s", buf);
		return;
	}

	snprintf(buf, 100, "ERROR link file error %d, exit\n", errno);
	Writen(fd, buf, strlen(buf));
	if (debug)
		printf("%s", buf);
	exit(-1);
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
			strcpy(buf, "ERROR open config file, exit\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				printf("%s", buf);
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
					printf("password ok, work_dir is %s\n", p);
				if (chroot(p) != 0) {
					perror("chroot");
					snprintf(buf, MAXLEN, "ERROR chroot to %s, exit\n", p);
					Writen(fd, buf, strlen(buf));
					if (debug)
						printf("%s", buf);
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
		if (debug)
			printf("%s", buf);
	}
	strcpy(buf, "OK password ok\n");
	Writen(fd, buf, strlen(buf));
	if (debug)
		printf("%s", buf);

	while (1)
		ProcessFile(fd);
}

void usage(void)
{
	printf("Usage:\n");
	printf("./hbackup_server -p port -f config_file [ -u user_name ] [ -6 ] [ -d ]\n");
	printf(" options:\n");
	printf("    -p port\n");
	printf("    -f config_file\n");
	printf("    -u user_name    change to user before write file\n");
	printf("\n");
	printf("    -6              enable ipv6 listen\n");
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

	while ((c = getopt(argc, argv, "p:f:u:6d")) != EOF)
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
				printf("user %s not found\n", work_user);
				exit(-1);
			}
			break;
		case '6':
			ipv6 = 1;
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
		umask(022);
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
		if (debug)
			printf("%s", "waiting client..\n");
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
