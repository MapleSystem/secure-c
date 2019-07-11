// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <stddef.h>

int foo(int *p, int *q) {
  if (p != NULL) {
    p = q;
    return *p; // expected-warning {{illegal access of nullable pointer}}
  }

  return 0;
}
