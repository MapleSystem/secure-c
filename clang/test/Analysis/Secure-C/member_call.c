// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
// This test is expected to fail until #185 is implemented
// XFAIL: *
#include <secure_c.h>

struct {
  int (*f)() __attribute__((nonnull));
} g;

int foo() {
  return g.f();
}
