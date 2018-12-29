/* hbackup
	  by james@ustc.edu.cn 2018.12.29
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

int days = 0;
char md5cache_file[MAXLEN];
char error_log_file[MAXLEN];
size_t total_file_len, upload_file_len;
size_t total_files, total_dirs, total_links;


int tcp_connect(const char *host, const char *serv)
{
	int sockfd, n;
	struct addrinfo	hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
		err_quit("tcp_connect error for %s, %s",
				 host, serv);
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;	/* ignore this one */

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;		/* success */

		close(sockfd);	/* ignore this one */
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL)	/* errno set from final connect() */
		err_sys("tcp_connect error for %s, %s", host, serv);

	freeaddrinfo(ressave);

	return(sockfd);
}
/* end tcp_connect */

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
		const char format[] = "ERROR open tmpfile %.*s for write\n";
		snprintf(buf, MAXLEN, format, (int)(MAXLEN - sizeof(format)), file_name);
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
		exit(-1);
	}
	if (debug)
		fprintf(stderr, "tmpfile %s open for write\n", file_name);
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
			snprintf(buf, 100, "ERROR file length %zu, only read %zu\n", file_len,
				 file_got);
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
	if (memcmp(md5sum, get_file_md5sum(file_name), 32) != 0) {
		unlink(file_name);
		strcpy(buf, "ERROR upload file md5sum error\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
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
		fprintf(stderr, "%s", buf);
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
		snprintf(buf, MAXLEN, "BYE FDL: %zu/%zu/%zu U/A: %zu/%zu\n", total_files,
			 total_dirs, total_links, upload_file_len, total_file_len);
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
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
			fprintf(stderr, "C->S %s ", buf);
		url_decode(p);
		snprintf(str, MAXLEN, "/data/%s", p);
		if (stat(str, &stbuf) == 0) {
			if (S_ISDIR(stbuf.st_mode)) {	// dir exists
				strcpy(buf, "OK mkdir, dir in server\n");
				Writen(fd, buf, strlen(buf));
				if (debug)
					fprintf(stderr, "%s", buf);
				return;
			}
			strcpy(buf, "ERROR mkdir, name exists, exit\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "%s", buf);
			exit(-1);
		}
		create_dir(str);
		strcpy(buf, "OK mkdir\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
		return;
	}

	if (memcmp(buf, "MKLINK ", 7) == 0) {	// MKLINK file_name linkto_name
		char strnew[MAXLEN], strold[MAXLEN];
		struct stat stbuf;
		total_links++;
		if (debug)
			fprintf(stderr, "C->S %s ", buf);
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
		if (lstat(strnew, &stbuf) == 0) {
			if (S_ISLNK(stbuf.st_mode)) {	// link exists
				strcpy(buf, "OK mklink, link in server\n");
				Writen(fd, buf, strlen(buf));
				if (debug)
					fprintf(stderr, "%s", buf);
				return;
			}
			strcpy(buf, "ERROR mklink, name exists, exit\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "%s", buf);
			exit(-1);
		}
		check_and_create_dir(strnew);
		if (symlink(strold, strnew) == 0) {
			strcpy(buf, "OK mklink\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "%s", buf);
		} else {
			strcpy(buf, "ERROR mklink, exit\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "%s", buf);
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
			fprintf(stderr, "%s", buf);
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
		fprintf(stderr, "C->S FILE %s %zu %s ", md5sum, file_len, file_name);

	struct stat stbuf;
	strcpy(hashed_file, get_hashed_file_name(md5sum, file_len));
	if (lstat(file_name, &stbuf) == 0) {	// file exists, check if the same, I use lstat, not stat, right?
		struct stat stbuf_hashed;
		if (lstat(hashed_file, &stbuf_hashed) == 0) {	// get hashed file stat
			if (stbuf.st_ino == stbuf_hashed.st_ino)	// the same file
				strcpy(buf, "OK same file in server\n");
			else
				strcpy(buf, "ERROR file exists, but not the same md5sum\n");
		} else
			strcpy(buf, "ERROR file exists, hashed file not exists\n");
		Writen(fd, buf, strlen(buf));
		if (debug)
			fprintf(stderr, "%s", buf);
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
			fprintf(stderr, "%s", buf);
		return;
	}

	snprintf(buf, 100, "ERROR link file error %d, exit\n", errno);
	Writen(fd, buf, strlen(buf));
	if (debug)
		fprintf(stderr, "%s", buf);
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
		if (fp == NULL) {
			strcpy(buf, "ERROR open config file\n");
			Writen(fd, buf, strlen(buf));
			if (debug)
				fprintf(stderr, "%s", buf);
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
					if (debug)
						fprintf(stderr, "%s", buf);
					exit(-1);
				}
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
			fprintf(stderr, "%s", buf);
	}
	strcpy(buf, "OK password ok\n");
	Writen(fd, buf, strlen(buf));
	if (debug)
		fprintf(stderr, "%s", buf);

	while (1)
		ProcessFile(fd);
}

void usage(void)
{
	printf("Usage:\n");
	printf("./hbackup [ -d ] [ -x exclude_file_regex ] [ -t n ] [ -e err_log_file ] \n"
	      "           [ -m md5cache.txt ] HostName Port Password File/DirToSend RemoteName\n");
	printf(" options:\n");
	printf("    -d              enable debug\n");
	printf("    -x regex        exlude file regex\n");
	printf("    -t n            skip n days old files\n");
	printf("    -e err_log_file error msg will be append to err_log_file, and continue to run\n");
	printf("    -m md5cache.txt md5sum_cache will be used if the file\'s mtime does not change.\n");
	printf("                    md5sum_cache_file must be created before use\n");
	printf("\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int c;
	int listenfd;

	while ((c = getopt(argc, argv, "dx:t:e:m:")) != EOF)
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'x':
			debug = 1;
			break;
		case 't':
			days = atoi(optarg);
			break;
		case 'e':
			strncpy(error_log_file, optarg, MAXLEN - 1);
			break;
		case 'm':
			strncpy(md5cache_file, optarg, MAXLEN - 1);
			break;
		}
	printf("argc = %d, optindex = %d\n", argc, optind);

	if( argc - optind != 5) 
		usage();

	if (debug) {
		printf("         debug = 1\n");
		printf("  exclude_regx = \n");
		printf("          days = %d\n", days);
		printf("error_log_file = %s\n", error_log_file);
		printf("md5cache_file =  %s\n", md5cache_file);
		printf("\n");
	}

exit(0);
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

	while (1) {
		int infd;
		int pid;
		if (debug)
			fprintf(stderr, "%s", "waiting client..\n");
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
