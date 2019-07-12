// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>

int *bar();

int foo(int *a) {
  int *b;
  if (a == NULL) return 0;

  b = bar();

  if (b == NULL) return 1;

  return *a + *b;
}
