// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <stddef.h>

int foo(int * _Nullable p) {
  goto skip_check;
  if (p != NULL) {
  skip_check:
    return *p; // expected-warning {{illegal access of nullable pointer}}
  }
  return 0;
}
