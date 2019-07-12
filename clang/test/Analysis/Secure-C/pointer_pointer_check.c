// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>

int *foo_n_n(int **p) {
  if (p == NULL)
    return NULL;
  return *p;
}

int foo_n_nn(int **p) {
  if (p == NULL)
    return 0;
  if (*p == NULL)
    return 0;
  return **p;
}
