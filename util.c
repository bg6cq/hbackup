#define MAXLEN 		16384
#define MAXLINE 	1024*1024

int daemon_proc;		/* set nonzero by daemon_init() */
int debug = 0;

char *get_file_md5sum(char *file_name)
{
	FILE *fp;
	MD5_CTX c;
	char buf[MAXLINE];
	int n;
	ssize_t bytes;
	unsigned char out[MD5_DIGEST_LENGTH];
	static char outhex[MD5_DIGEST_LENGTH * 2 + 1];

	outhex[0] = 0;
	MD5_Init(&c);
	fp = fopen(file_name, "r");
	if (fp == NULL)
		return outhex;

	bytes = fread(buf, 1, MAXLINE, fp);
	while (bytes > 0) {
		MD5_Update(&c, buf, bytes);
		bytes = fread(buf, 1, MAXLINE, fp);
	}
	fclose(fp);
	MD5_Final(out, &c);
	for (n = 0; n < MD5_DIGEST_LENGTH; n++) {
		snprintf(outhex + n * 2, 3, "%02x", out[n]);
	}
	if (debug)
		fprintf(stderr, "md5sum of file %s is %s\n", file_name, outhex);
	return outhex;
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

	if (daemon_proc)
		syslog(level, "%s", buf);
	else {
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

	snprintf(st_buf, 200, "%04d%02d%02d %02d:%02d:%02d.%06ld", tm->tm_year + 1900,
		 tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);
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

int url_encode(const char *str, const int strSize, char *result, const int resultSize)
{
	int i;
	int j = 0;		//for result index
	char ch;

	if ((str == NULL) || (result == NULL) || (strSize <= 0) || (resultSize <= 0)) {
		return 0;
	}

	for (i = 0; i < strSize; i++) {
		if (j >= resultSize - 1) {
			result[0] = 0;
			return 0;
		}
		ch = str[i];
		if (((ch >= 'A') && (ch <= 'Z')) ||
		    ((ch >= 'a') && (ch <= 'z')) || ((ch >= '0') && (ch <= '9'))) {
			result[j++] = ch;
		} else if (ch == ' ') {
			result[j++] = '+';
		} else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
			result[j++] = ch;
		} else {
			if (j + 3 < resultSize - 1) {
				sprintf(result + j, "%%%02X", (unsigned char)ch);
				j += 3;
			} else {
				result[0] = 0;
				return 0;
			}
		}
	}
	result[j] = '\0';
	return j;
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
