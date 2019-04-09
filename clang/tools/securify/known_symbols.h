#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

void *_Nullable malloc(size_t size);
void free(void *_Nonnull ptr);
void *_Nullable calloc(size_t nmemb, size_t size);
void *_Nullable realloc(void *_Nullable ptr, size_t size);
void *_Nullable reallocarray(void *_Nonnull ptr, size_t nmemb, size_t size);

extern FILE *_Nonnull stdin;  /* Standard input stream.  */
extern FILE *_Nonnull stdout; /* Standard output stream.  */
extern FILE *_Nonnull stderr; /* Standard error output stream.  */

int printf(const char *_Nonnull format, ...);
int fprintf(FILE *_Nonnull stream, const char *_Nonnull format, ...);
int dprintf(int fd, const char *_Nonnull format, ...);
int sprintf(char *_Nonnull str, const char *_Nonnull format, ...);
int snprintf(char *_Nonnull str, size_t size, const char *_Nonnull format, ...);
int vprintf(const char *_Nonnull format, va_list ap);
int vfprintf(FILE *_Nonnull stream, const char *_Nonnull format, va_list ap);
int vdprintf(int fd, const char *_Nonnull format, va_list ap);
int vsprintf(char *_Nonnull str, const char *_Nonnull format, va_list ap);
int vsnprintf(char *_Nonnull str, size_t size, const char *_Nonnull format,
              va_list ap);

int open(const char *_Nonnull pathname, int flags, ...);
int creat(const char *_Nonnull pathname, mode_t mode);
int openat(int dirfd, const char *_Nonnull pathname, int flags, ...);

int stat(const char *_Nonnull pathname, struct stat *_Nonnull statbuf);
int fstat(int fd, struct stat *_Nonnull statbuf);
int lstat(const char *_Nonnull pathname, struct stat *_Nonnull statbuf);

ssize_t read(int fd, void *_Nullable buf, size_t count);
ssize_t write(int fd, const void *_Nullable buf, size_t count);

FILE *_Nullable fopen(const char *_Nonnull pathname, const char *_Nonnull mode);
FILE *_Nullable fdopen(int fd, const char *_Nonnull mode);
FILE *_Nullable freopen(const char *_Nonnull pathname,
                        const char *_Nonnull mode, FILE *_Nonnull stream);

int fclose(FILE *_Nonnull stream);

size_t fread(void *_Nonnull ptr, size_t size, size_t nmemb,
             FILE *_Nonnull stream);
size_t fwrite(const void *_Nonnull ptr, size_t size, size_t nmemb,
              FILE *_Nonnull stream);

int fflush(FILE *_Nonnull stream);

int fgetc(FILE *_Nonnull stream);
char *_Nullable fgets(char *_Nonnull s, int size, FILE *_Nonnull stream);
int getc(FILE *_Nonnull stream);
int getchar(void);
int ungetc(int c, FILE *_Nonnull stream);

void clearerr(FILE *_Nonnull stream);
int feof(FILE *_Nonnull stream);
int ferror(FILE *_Nonnull stream);
int fileno(FILE *_Nonnull stream);

// From string.h
char *_Nonnull strcat(char *_Nonnull dest, const char *_Nonnull src);
char *_Nonnull strncat(char *_Nonnull dest, const char *_Nonnull src, size_t n);
size_t strlen(const char *_Nonnull s);
int strcmp(const char *_Nonnull s1, const char *_Nonnull s2);
int strncmp(const char *_Nonnull s1, const char *_Nonnull s2, size_t n);
char *_Nonnull strcpy(char *_Nonnull dest, const char *_Nonnull src);
char *_Nonnull strncpy(char *_Nonnull dest, const char *_Nonnull src, size_t n);

// From ctype.h
extern const unsigned short int *_Nonnull *_Nonnull __ctype_b_loc(void) __THROW
    __attribute__((__const__));
extern const __int32_t *_Nonnull *_Nonnull __ctype_tolower_loc(void) __THROW
    __attribute__((__const__));
extern const __int32_t *_Nonnull *_Nonnull __ctype_toupper_loc(void) __THROW
    __attribute__((__const__));

// From errno.h
extern int *_Nonnull __errno_location(void) __THROW __attribute_const__;

int utime(const char *_Nonnull filename, const struct utimbuf *_Nullable times);
int utimes(const char *_Nonnull filename, const struct timeval times[2]);

char *_Nullable getenv(const char *_Nonnull name);
