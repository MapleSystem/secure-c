#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

void * _Nullable malloc(size_t size);
void free(void * _Nonnull ptr);
void * _Nullable calloc(size_t nmemb, size_t size);
void * _Nullable realloc(void * _Nullable ptr, size_t size);
void * _Nullable reallocarray(void * _Nonnull ptr, size_t nmemb, size_t size);

extern FILE * _Nonnull stdin;    /* Standard input stream.  */
extern FILE * _Nonnull stdout;   /* Standard output stream.  */
extern FILE * _Nonnull stderr;   /* Standard error output stream.  */


int printf(const char * _Nonnull format, ...);
int fprintf(FILE * _Nonnull stream, const char * _Nonnull format, ...);
int dprintf(int fd, const char * _Nonnull format, ...);
int sprintf(char * _Nonnull str, const char * _Nonnull format, ...);
int snprintf(char * _Nonnull str, size_t size, const char * _Nonnull format, ...);
int vprintf(const char * _Nonnull format, va_list ap);
int vfprintf(FILE * _Nonnull stream, const char * _Nonnull format, va_list ap);
int vdprintf(int fd, const char * _Nonnull format, va_list ap);
int vsprintf(char * _Nonnull str, const char * _Nonnull format, va_list ap);
int vsnprintf(char * _Nonnull str, size_t size, const char * _Nonnull format, va_list ap);

FILE * _Nullable fopen(const char * _Nonnull pathname, const char * _Nonnull mode);
FILE * _Nullable fdopen(int fd, const char * _Nonnull mode);
FILE * _Nullable freopen(const char * _Nonnull pathname, const char * _Nonnull mode, FILE * _Nonnull stream);

int fclose(FILE * _Nonnull stream);

size_t fread(void * _Nonnull ptr, size_t size, size_t nmemb, FILE * _Nonnull stream);
size_t fwrite(const void * _Nonnull ptr, size_t size, size_t nmemb,
              FILE * _Nonnull stream);

int fflush(FILE * _Nonnull stream);

int fgetc(FILE * _Nonnull stream);
char * _Nullable fgets(char * _Nonnull s, int size, FILE * _Nonnull stream);
int getc(FILE * _Nonnull stream);
int getchar(void);
int ungetc(int c, FILE * _Nonnull stream);

void clearerr(FILE * _Nonnull stream);
int feof(FILE * _Nonnull stream);
int ferror(FILE * _Nonnull stream);
int fileno(FILE * _Nonnull stream);


char * _Nonnull strcat(char * _Nonnull dest, const char * _Nonnull src);
char * _Nonnull strncat(char * _Nonnull dest, const char * _Nonnull src, size_t n);
