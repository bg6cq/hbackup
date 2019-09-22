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
#include <linux/limits.h>
#include <libgen.h>
#include <dirent.h>

#include "uthash.h"

#include "util.c"

char md5cache_file[PATH_MAX];
FILE *md5cache_fp;

char error_log_file[PATH_MAX];
FILE *error_log_fp;

char local_file_name[PATH_MAX];
char remote_file_name[PATH_MAX];

int haserror = 0;
size_t total_files, total_dirs, total_links, skipped_files, total_file_len, upload_file_len;

struct my_struct {
	const char *filename;	/* key */
	time_t filetime;
	int used;
	char md5s[MD5_DIGEST_LENGTH * 2 + 1];
	UT_hash_handle hh;	/* makes this structure hashable */
};

struct my_struct *md5sum_cache = NULL;
int md5sum_cache_lookup, md5sum_cache_hit, md5sum_cache_update;

void update_md5sum_cache(char *name, time_t ft, char *md5s)
{
	struct my_struct *s = NULL;
	char *p;
	if (md5cache_fp == NULL)
		return;
	HASH_FIND_STR(md5sum_cache, name, s);
	if (s) {
		if (debug)
			printf("update md5sum_cache %lu %s %s\n", ft, md5s, name);
		s->filetime = ft;
		s->used = 1;
		strncpy(s->md5s, md5s, MD5_DIGEST_LENGTH * 2);
		return;
	}
	s = (struct my_struct *)malloc(sizeof(struct my_struct));
	p = malloc(strlen(name) + 1);
	if (p == NULL) {
		printf("malloc error\n");
		exit(-1);
	}
	strcpy(p, name);
	s->filename = p;
	s->filetime = ft;
	s->used = 1;
	strncpy(s->md5s, md5s, MD5_DIGEST_LENGTH * 2);
	HASH_ADD_KEYPTR(hh, md5sum_cache, s->filename, strlen(s->filename), s);
	if (debug)
		printf("add md5sum_cache %lu %s %s\n", ft, md5s, name);
}

void load_md5sum_cache()
{
	char buf[MAXLEN];
	int cnt = 0;

	if (md5cache_fp == NULL)
		return;
	printf("loading md5sum_cache from %s ...", md5cache_file);
	while (fgets(buf, MAXLEN, md5cache_fp)) {
		char *p1, *p2, *p3;
		p1 = buf;
		p2 = buf;
		while (*p2 && (*p2 != ' '))
			p2++;
		if (*p2 == 0) {
			printf("skip %s", buf);
			continue;
		}
		p3 = p2 + 1;
		while (*p3 && (*p3 != ' '))
			p3++;
		if (*p3 == 0) {
			printf("skip %s", buf);
			continue;
		}
		*p2 = 0;
		p2++;
		*p3 = 0;
		p3++;
		if (*p3 == 0)
			continue;
		if (p3[strlen(p3) - 1] == '\n')
			p3[strlen(p3) - 1] = 0;
		time_t ft;
		if (sscanf(p1, "%lu", &ft) != 1)
			continue;
		if (strlen(p2) != MD5_DIGEST_LENGTH * 2)
			continue;
		if (strlen(p3) <= 0)
			continue;
		if (debug)
			printf("cache %lu %s %s\n", ft, p2, p3);
		update_md5sum_cache(p3, ft, p2);
		cnt += 1;
	}
	printf("loaded md5sum_cache %d lines\n", cnt);
}

void save_md5sum_cache()
{
	if (md5cache_fp == NULL)
		return;
	rewind(md5cache_fp);
	ftruncate(fileno(md5cache_fp), 0);
	struct my_struct *s;

	for (s = md5sum_cache; s != NULL; s = s->hh.next) {
		if (s->used)
			fprintf(md5cache_fp, "%lu %s %s\n", s->filetime, s->md5s, s->filename);
	}
	fclose(md5cache_fp);
}

time_t file_mtime(char *fname)
{
	struct stat buf;
	if (stat(fname, &buf) == 0)
		return buf.st_mtime;
	return 0;
}

char *file_md5sum(char *fname)
{
	time_t ft;
	if (md5cache_fp) {
		struct my_struct *s;
		ft = file_mtime(fname);
		HASH_FIND_STR(md5sum_cache, fname, s);
		if (s) {
			md5sum_cache_lookup++;
			if (s->filetime == ft) {
				s->used = 1;
				md5sum_cache_hit++;
				return s->md5s;
			}
		}
	}
	char *md5s;
	md5s = get_file_md5sum(fname);
	if (md5cache_fp) {
		md5sum_cache_update++;
		update_md5sum_cache(fname, ft, md5s);
	}
	return md5s;
}

void log_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	haserror = 1;
	if (error_log_fp) {
		fprintf(error_log_fp, "%s ", stamp());
		vfprintf(error_log_fp, fmt, ap);
		va_end(ap);
		fflush(error_log_fp);
	} else {
		vprintf(fmt, ap);
		va_end(ap);
		exit(-1);
	}
}

int tcp_connect(const char *host, const char *serv)
{
	int sockfd, n;
	struct addrinfo hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		err_quit("tcp_connect error for %s, %s", host, serv);
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;	/* ignore this one */

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;	/* success */

		close(sockfd);	/* ignore this one */
	} while ((res = res->ai_next) != NULL);

	if (res == NULL)	/* errno set from final connect() */
		err_sys("tcp_connect error for %s, %s", host, serv);

	freeaddrinfo(ressave);

	struct timeval timeout;
	timeout.tv_sec = 1200;
	timeout.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	return (sockfd);
}

/* end tcp_connect */

int SendPass(int fd, char *pass)
{
	char buf[MAXLEN];
	int n;
	snprintf(buf, MAXLEN, "PASS %s\n", pass);
	if (debug)
		printf("C: %s", buf);
	Writen(fd, buf, strlen(buf));
	n = Readline(fd, buf, MAXLEN);
	buf[n] = 0;
	if (n == 0) {
		printf("read 0, exit\n");
		exit(-1);
	}
	if (debug)
		printf("S: %s", buf);
	if (memcmp(buf, "OK", 2) == 0)
		return 0;
	printf("Got %s, exit\n", buf);
	exit(-1);
}

void send_dir(int fd, char *remote_name)
{
	char buf[MAXLEN];
	int n;
	total_dirs++;
	memcpy(buf, "MKDIR ", 6);
	n = url_encode(remote_name, strlen(remote_name), buf + 6, MAXLEN - 7);
	if (n == 0) {
		printf("error when url_encode %s\n", remote_name);
		exit(-1);
	}
	buf[6 + n] = '\n';
	buf[6 + n + 1] = 0;
	if (debug)
		printf("C: %s", buf);
	Writen(fd, buf, 6 + n + 1);

	n = Readline(fd, buf, MAXLEN);
	buf[n] = 0;
	if (n == 0) {
		printf("read 0, exit\n");
		exit(-1);
	}
	if (debug)
		printf("S: %s", buf);
	if (memcmp(buf, "OK", 2) == 0)
		return;
	log_err("%s %s", remote_name, buf);
	printf("S: %s", buf);
}

void send_link(int fd, char *remote_name, char *linkto)
{
	char buf[MAXLEN];
	int n, n1, n2;
	total_links++;
	memcpy(buf, "MKLINK ", 7);
	n1 = url_encode(remote_name, strlen(remote_name), buf + 7, MAXLEN - 8);
	if (n1 == 0) {
		printf("error when url_encode %s\n", remote_name);
		exit(-1);
	}
	buf[7 + n1] = ' ';
	n1++;
	n2 = url_encode(linkto, strlen(linkto), buf + n1 + 7, MAXLEN - 8 - n1);
	if (n2 == 0) {
		printf("error when url_encode %s\n", linkto);
		exit(-1);
	}

	buf[7 + n1 + n2] = '\n';
	buf[7 + n1 + n2 + 1] = 0;
	if (debug)
		printf("C: %s", buf);
	Writen(fd, buf, 7 + n1 + n2 + 1);
	n = Readline(fd, buf, MAXLEN);
	buf[n] = 0;
	if (n == 0) {
		printf("read 0, exit\n");
		exit(-1);
	}
	if (debug)
		printf("S: %s", buf);
	if (memcmp(buf, "OK", 2) == 0)
		return;
	log_err("%s %s", remote_name, buf);
	printf("S: %s", buf);
}

void send_file(int fd, char *local_file_name, char *remote_name)
{
	char *filemd5sum;
	char buf[MAXLEN];
	int n, n1, n2;
	size_t file_size;
	struct stat buffer;
	total_files++;
	filemd5sum = file_md5sum(local_file_name);
	if (stat(local_file_name, &buffer) != 0) {
		log_err("could not stat file %s, skip\n", local_file_name);
		printf("could not stat file %s, skip\n", local_file_name);
		return;
	}
	file_size = buffer.st_size;
	total_file_len += file_size;
	n1 = snprintf(buf, MAXLEN, "FILE %s %lu ", filemd5sum, file_size);

	n2 = url_encode(remote_name, strlen(remote_name), buf + n1, MAXLEN - n1 - 1);
	if (n2 == 0) {
		printf("error when url_encode %s\n", remote_name);
		exit(-1);
	}
	buf[n1 + n2] = '\n';
	buf[n1 + n2 + 1] = 0;
	if (debug)
		printf("C: %s", buf);
	Writen(fd, buf, n1 + n2 + 1);

	n = Readline(fd, buf, MAXLEN);
	buf[n] = 0;
	if (n == 0) {
		printf("read 0, exit\n");
		exit(-1);
	}
	if (debug)
		printf("S: %s", buf);
	if (memcmp(buf, "OK", 2) == 0)
		return;
	else if (memcmp(buf, "ERROR", 5) == 0) {
		log_err("%s --> %s %s", local_file_name, remote_name, buf);
		return;
	}
	if (memcmp(buf, "DATA", 4) != 0) {
		printf("S: %s", buf);
		exit(-1);
	}

	if (debug)
		printf("I will send file\n");

	FILE *fp;
	fp = fopen(local_file_name, "r");
	if (fp == NULL) {
		printf("open file error: %s\n", local_file_name);
		exit(-1);
	}
	size_t bytes_send = 0;

	while (1) {
		size_t need_read = file_size - bytes_send;
		size_t bytes_read;
		if (need_read > 0) {
			if (need_read > MAXLEN)
				bytes_read = fread(buf, 1, MAXLEN, fp);
			else
				bytes_read = fread(buf, 1, need_read, fp);
			if (bytes_read > 0) {
				upload_file_len += bytes_read;
				Writen(fd, buf, bytes_read);
				bytes_send += bytes_read;
			} else
				break;
		} else
			break;
	}
	fclose(fp);
	n = Readline(fd, buf, MAXLEN);
	buf[n] = 0;
	if (n == 0) {
		printf("read 0, exit\n");
		exit(-1);
	}
	if (debug)
		printf("S: %s", buf);
	if (memcmp(buf, "OK", 2) == 0)
		return;
	else if (memcmp(buf, "ERROR", 5) == 0) {
		printf("S: %s", buf);
		log_err("%s --> %s %s", local_file_name, remote_name, buf);
		return;
	}
	printf("S: %s", buf);
	exit(-1);
}

void send_whole_dir(int fd, char *dir, char *remote_dir)
{
	DIR *dirp;
	struct dirent *direntp;
	dirp = opendir(dir);
	if (dirp == NULL) {
		printf("opendir error %s\n", dir);
		exit(-1);
	}
	while ((direntp = readdir(dirp)) != NULL) {
		struct stat st;
		char lfile_name[PATH_MAX];
		if (strcmp(direntp->d_name, ".") == 0)
			continue;
		if (strcmp(direntp->d_name, "..") == 0)
			continue;
		snprintf(lfile_name, PATH_MAX, "%s/%s", dir, direntp->d_name);
		if (lstat(lfile_name, &st) != 0) {
			printf("lstat error: %s\n", lfile_name);
			exit(-1);
		}
		if (S_ISDIR(st.st_mode)) {
			char buf[PATH_MAX];
			if (debug)
				printf("DIR %s\n", lfile_name);
			printf("%s\n", lfile_name);
			snprintf(buf, PATH_MAX, "%s/%s", remote_dir, direntp->d_name);
			send_dir(fd, buf);
			send_whole_dir(fd, lfile_name, buf);
		} else if (S_ISLNK(st.st_mode)) {
			char buf[PATH_MAX], lpath[PATH_MAX];
			int n;
			if (debug)
				printf("LINK %s\n", lfile_name);
			n = readlink(lfile_name, lpath, PATH_MAX - 1);
			if (n == -1) {
				printf("readlink error %s\n", lfile_name);
				exit(-1);
			}
			lpath[n] = 0;
			printf("%s LINK\n", lfile_name);
			snprintf(buf, PATH_MAX, "%s/%s", remote_dir, direntp->d_name);
			send_link(fd, buf, lpath);
		} else if (S_ISREG(st.st_mode)) {
			char buf[PATH_MAX];
			if (debug)
				printf("FILE %s\n", lfile_name);
			printf("%s\n", lfile_name);
			snprintf(buf, PATH_MAX, "%s/%s", remote_dir, direntp->d_name);
			send_file(fd, lfile_name, buf);
		} else
			printf("%s SKIP\n", lfile_name);
	}
	closedir(dirp);
}

void end_backup(int fd)
{
	char buf[MAXLEN];
	int n;
	sprintf(buf, "END\n");
	Writen(fd, buf, strlen(buf));
	n = Readline(fd, buf, MAXLEN);
	buf[n] = 0;
	if (n == 0) {
		printf("read 0, exit\n");
		exit(-1);
	}
	printf("End of backup, S: %s", buf);

	printf("Files/Dirs/Links: %zu/%zu/%zu, skipped %zu, UploadBytes/TotalBytes: %zu/%zu\n",
	       total_files, total_dirs, total_links, skipped_files,
	       upload_file_len, total_file_len);
	if (md5cache_fp)
		save_md5sum_cache();
	if (haserror) {
		printf("Encountered error when backuping file\n");
		printf("Error msg append to %s, please check it\n", error_log_file);
	}
	exit(haserror);
}

void usage(void)
{
	printf("Version: %s\n", VERSION);
	printf("Usage:\n");
	printf("./hbackup [ -d ] [ -e err_log_file ] \n"
	       "           [ -m md5cache.txt ] HostName Port Password File/DirToSend RemoteName\n");
	printf(" options:\n");
	printf("    -d              enable debug\n");
	printf
	    ("    -e err_log_file error msg will be append to err_log_file, and continue to run\n");
	printf
	    ("    -m md5cache.txt md5sum_cache will be used if the file\'s mtime does not change.\n");
	printf("                    md5sum_cache_file must be created before use\n");
	printf("\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	int c;
	int fd;

	while ((c = getopt(argc, argv, "de:m:")) != EOF)
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'e':
			strncpy(error_log_file, optarg, PATH_MAX);
			break;
		case 'm':
			strncpy(md5cache_file, optarg, PATH_MAX);
			break;
		}

	if (argc - optind != 5)
		usage();

	strncpy(local_file_name, argv[optind + 3], PATH_MAX);
	strncpy(remote_file_name, argv[optind + 4], PATH_MAX);

	while (strlen(local_file_name) > 0 && local_file_name[strlen(local_file_name) - 1] == '/')
		local_file_name[strlen(local_file_name) - 1] = 0;
	while (strlen(remote_file_name) > 0
	       && remote_file_name[strlen(remote_file_name) - 1] == '/')
		remote_file_name[strlen(remote_file_name) - 1] = 0;
	if (debug) {
		printf("           debug = 1\n");
		printf("    exclude_regx = \n");
		printf("  error_log_file = %s\n", error_log_file);
		printf("   md5cache_file = %s\n", md5cache_file);
		printf("============================\n");
		printf("            host = %s\n", argv[optind]);
		printf("            port = %s\n", argv[optind + 1]);
		printf("            pass = %s\n", argv[optind + 2]);
		printf(" local_file_name = %s\n", local_file_name);
		printf("remote_file_name = %s\n", remote_file_name);
		printf("\n");
	}

	if (md5cache_file[0]) {
		md5cache_fp = fopen(md5cache_file, "r+");
		if (md5cache_fp == NULL) {
			printf("open file %s error, exit\n", md5cache_file);
			exit(-1);
		}
		load_md5sum_cache();
	}
	if (error_log_file[0]) {
		error_log_fp = fopen(error_log_file, "a");
		if (error_log_fp == NULL) {
			printf("open error log file %s error, exit\n", error_log_file);
			exit(-1);
		}
	}
	fd = tcp_connect(argv[optind], argv[optind + 1]);
	SendPass(fd, argv[optind + 2]);

	struct stat st;
	if (lstat(local_file_name, &st) != 0) {
		printf("lstat error: %s\n", local_file_name);
		exit(-1);
	}
	if (S_ISDIR(st.st_mode)) {
		if (debug)
			printf("DIR %s\n", local_file_name);
		printf("%s\n", local_file_name);
		send_whole_dir(fd, local_file_name, remote_file_name);
		end_backup(fd);
		exit(haserror);
	} else if (S_ISLNK(st.st_mode)) {
		char buf[PATH_MAX], lpath[PATH_MAX];
		int n;
		if (debug)
			printf("LINK %s\n", local_file_name);
		n = readlink(local_file_name, lpath, PATH_MAX - 1);
		if (n == -1) {
			printf("readlink error %s\n", local_file_name);
			exit(-1);
		}
		lpath[n] = 0;
		printf("%s LINK\n", local_file_name);
		if (remote_file_name[strlen(remote_file_name)-1] == '/')
			snprintf(buf, PATH_MAX, "%s%s", remote_file_name, basename(local_file_name));
		else
			snprintf(buf, PATH_MAX, "%s", remote_file_name);
		send_link(fd, buf, lpath);
		exit(haserror);
	} else if (S_ISREG(st.st_mode)) {
		char buf[PATH_MAX];
		if (debug)
			printf("FILE %s\n", local_file_name);
		printf("%s\n", local_file_name);
		if (remote_file_name[strlen(remote_file_name)-1] == '/')
			snprintf(buf, PATH_MAX, "%s%s", remote_file_name, basename(local_file_name));
		else
			snprintf(buf, PATH_MAX, "%s", remote_file_name);
		send_file(fd, local_file_name, buf);
		exit(haserror);
	} else {
		printf("%s SKIP\n", local_file_name);
	}
	exit(-1);
}
