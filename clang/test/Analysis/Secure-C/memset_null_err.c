// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// This test is expected to fail until #183 and #135 are implemented
// XFAIL: *
#include <secure_c.h>

void foo(int **p)
    __attribute__((secure_c_in(p, nonnull), secure_c_in(*p, nonnull))) {
  // expected-warning@+1 {{unsafe promotion from nullable pointer}}
  memset(p, 0, sizeof(int *));
}
