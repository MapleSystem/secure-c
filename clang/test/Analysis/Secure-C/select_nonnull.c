// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <secure_c.h>
#include <stddef.h>

int foo(int a, int *_Nonnull p, int *_Nonnull q)
    __attribute__((secure_c_in(p, nonnull), secure_c_in(q, nonnull))) {
  return *(a ? p : q);
}
