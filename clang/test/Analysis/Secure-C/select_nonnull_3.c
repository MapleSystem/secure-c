// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <secure_c.h>
#include <stddef.h>

int *foo(int *p, int *q)
    __attribute__((secure_c_in(q, nonnull), secure_c_out(foo, nonnull))) {
  return (p != NULL) ? p : q;
}
