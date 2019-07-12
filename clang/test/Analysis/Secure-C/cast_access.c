// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>

struct Foo {
  unsigned int a;
};

int foo(void *f) {
  if (f == NULL)
    return 0;

  if (((struct Foo *)f)->a > 0)
    return 1;

  return -1;
}
