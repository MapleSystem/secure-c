// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <secure_c.h>

int foo_nn_nn(int **p)
    __attribute__((secure_c_in(p, nonnull), secure_c_in(*p, nonnull))) {
  return **p;
}
