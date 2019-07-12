// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>

int foo(int *x, int b) {
  if (x != NULL) {
    if (b > 0) {
      return *x + b;
    }
  }
  return 0;
}
