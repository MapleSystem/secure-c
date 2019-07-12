// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>
#include <secure_c.h>

void foo(int *ptr) __attribute__((secure_c_in(ptr, nonnull)));

int gX;

void bar() {
  int *x = &gX;
  foo(x);
}
