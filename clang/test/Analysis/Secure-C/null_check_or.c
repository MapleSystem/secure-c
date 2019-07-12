// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>

int foo(int *a, int *b) {
  if (a == NULL || b == NULL) {
    return 0;
  } else {
    return *a + *b;
  }
}
