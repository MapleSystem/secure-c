// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// This test is expected to fail until #186 is resolved
// XFAIL: *
#include <secure_c.h>
#include <stddef.h>

int foo(int *x) __attribute__((secure_c_in(x, nonnull))) {
  if (x != NULL) { // expected-warning {{redundant null check}}
    return *x;
  }
  return 0;
}
