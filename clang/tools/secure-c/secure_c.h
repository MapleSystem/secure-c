#ifndef SECURE_C_H
#define SECURE_C_H 1

#include <stdio.h>
#include <stdlib.h>

#ifndef __has_feature      // Optional of course.
#define __has_feature(x) 0 // Compatibility with non-clang compilers.
#endif
#if !__has_feature(nullability)
#define _Nonnull
#define _Nullable
#endif

static void *_Nonnull _CheckNonNull(const char *_Nonnull file, int line,
                                    const char *_Nonnull func,
                                    void *_Nullable p) {
  if (__builtin_expect(p == ((void *)0), 1)) {
    fprintf(stderr, "%s:%d: %s: illegal use of NULL pointer\n", file, line,
            func);
    abort();
  }
  return p;
}

#endif
