// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <secure_c.h>

void foo1(int *ptr) __attribute__((secure_c_in(ptr, nonnull)));
void foo2(char *ptr) __attribute__((secure_c_in(ptr, nonnull)));

int bar() {
  int ary[10];
  foo1(ary);
  foo2("hello");
  char *p2 = "world";
  return 0;
}
