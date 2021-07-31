/*
 * utils.c: common functions used by namedhcp* programs
 * Copyright 2017-2021 Renzo Davoli, Virtualsquare & University of Bologna
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

static int logok=0;
static char *progname;

void startlog(char *prog, int use_syslog) {
	progname = prog;
	if (use_syslog) {
		openlog(progname, LOG_PID, 0);
		printlog(LOG_INFO, "%s started", progname);
		logok=1;
	}
}

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority, format, arg);
	else {
		fprintf(stderr, "%s: ", progname);
		vfprintf(stderr, format, arg);
		fprintf(stderr, "\n");
	}
	va_end (arg);
}

void save_pidfile(char *pidfile, char *cwd)
{
	char pidfile_path[PATH_MAX];

	if(pidfile[0] != '/')
		snprintf(pidfile_path, PATH_MAX, "%s/%s", cwd, pidfile);
	else
		snprintf(pidfile_path, PATH_MAX, "%s", pidfile);

	int fd = open(pidfile_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	FILE *f;

	if(fd == -1) {
		printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

void packetdump(FILE *f, void *arg,ssize_t len) {
	unsigned char *buf=arg;
	ssize_t lines=(len+15)>>4;
	ssize_t line;
	for (line=0; line<lines; line++) {
		ssize_t i;
		for (i=0; i<16; i++) {
			int n=line<<4 | i;
			if (n<len)
				fprintf(f, "%02x ",buf[n]);
			else
				fprintf(f, "   ");
		}
		fprintf(f, " | ");
		for (i=0; i<16; i++) {
			int n=line<<4 | i;
			if (n<len)
				fprintf(f, "%c", isprint(buf[n])?buf[n]:'.');
		}
		fprintf(f, "\n");
	}
}

void printin6addr(FILE *f, void *addr) {
	char addrbuf[INET6_ADDRSTRLEN];
	fprintf(f, "%s", inet_ntop(AF_INET6, addr, addrbuf, INET6_ADDRSTRLEN));
}

/* convert a name in DNS format (cuncompressed)
	 host.domain.org. -> \004host\006domain\003org\000.
	 conversion is correct whether or not there is the final dot.
	 returns the length in byte of the converted string */
/* out must have at least the same size of name, i.e. strlen(name) + 1 */
unsigned int name2udns(const char *name, char *out) {
	const char *limit = name + strlen(name);
	if (name == limit)
		return out[0] = 0, 1;
	else {
		int len = 0;
		if (limit[-1] == '.') limit--;
		while (name < limit) {
			char *itemlen = out++;
			while (*name !=0 && *name != '.')
				*out++ = *name++;
			if (*name == '.') name++;
			*itemlen = out - itemlen - 1;
			len += (*itemlen) + 1;
		}
		*out=0;
		return len + 1;
	}
}

void fput_uint8(FILE *f, uint8_t data) {
	fputc(data, f);
}

void fput_uint16(FILE *f, uint16_t data) {
	fputc(data >> 8, f);
	fputc(data, f);
}

void fput_uint32(FILE *f, uint32_t data) {
	fputc(data >> 24, f);
	fputc(data >> 16, f);
	fputc(data >> 8, f);
	fputc(data, f);
}

void fput_data(FILE *f, const void *data, uint16_t len) {
	fwrite(data, len, 1, f);
}

void fput_name(FILE *f, const char *name) {
	char dnsname[strlen(name) + 1];
	int len = name2udns(name, dnsname);
	fput_data(f, dnsname, len);
}

uint8_t fget_uint8(FILE *f) {
	int byte = fgetc(f);
	return (byte > 0) ? byte : 0;
}

uint16_t fget_uint16(FILE *f) {
	return (fget_uint8(f) << 8) | fget_uint8(f);
}

uint32_t fget_uint32(FILE *f) {
	return (fget_uint8(f) << 24) | (fget_uint8(f) << 16) |
		(fget_uint8(f) << 8) | fget_uint8(f);
}

void *fget_data(FILE *f, void *data, uint16_t len) {
	size_t retval = fread(data, len, 1, f);
	(void) retval;
	return data;
}

char *fget_name(FILE *f, char *name, int namelen) {
	uint8_t len;
	if (name == NULL) {
		while((len = fget_uint8(f)) != 0)
			fseek(f, len, SEEK_CUR);
	} else {
		int index = 0;
		namelen--;
		while ((len = fget_uint8(f)) != 0 && index < namelen) {
			int i;
			if (index > 0)
				name[index++] = '.';
			for (i = 0; i < len && index < namelen; i++)
				name[index++] = fget_uint8(f);
		}
		name[index] = 0;
	}
	return name;
}
