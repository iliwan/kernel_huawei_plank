
#ifndef __LIBC_H__
#define __LIBC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

void *malloc(unsigned int sz);
void free(void * addr);
void *memcpy(void *_dst, const void *_src, unsigned int len);
void *memset(void *_p, unsigned int v, unsigned int count);
int strlen(const char *s);
int strcmp(const char *a, const char *b);
char *strcpy(char *dst, const char *src);

#ifdef __cplusplus
}
#endif

#endif /* __LIBC_H__ */
