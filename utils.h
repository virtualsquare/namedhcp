#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <syslog.h>

void fput_uint8(FILE *f, uint8_t data);
void fput_uint16(FILE *f, uint16_t data);
void fput_uint32(FILE *f, uint32_t data);
void fput_data(FILE *f, const void *data, uint16_t len);
void fput_name(FILE *f, const char *name);
uint8_t fget_uint8(FILE *f);
uint16_t fget_uint16(FILE *f);
uint32_t fget_uint32(FILE *f);
void *fget_data(FILE *f, void *data, uint16_t len);
char *fget_name(FILE *f, char *name, int namelen);

void startlog(char *prog, int use_syslog);
void printlog(int priority, const char *format, ...);
void save_pidfile(char *pidfile, char *cwd);

void packetdump(FILE *f, void *arg,ssize_t len);
void printin6addr(FILE *f, void *addr);

#endif
