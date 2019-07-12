// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <stddef.h>

int foo(int *a, int b) {
  if (a != NULL || b > 0) {
    return *a + b; // expected-warning {{illegal access of nullable pointer}}
  }
  return b;
}
