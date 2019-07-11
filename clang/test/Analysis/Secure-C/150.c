// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <stddef.h>
#include <secure_c.h>

int foo(int *_Nullable p, int *_Nonnull q)
    __attribute__((secure_c_in(q, nonnull))) {
  return *((p != NULL) ? p : q);
}

// expected-no-diagnostics
