// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>
#include <stdlib.h>

_Noreturn int panic(int err) {
  exit(err);
}

int foo(int *x) {
  if (x == NULL)
    panic(1);

  return *x;
}
