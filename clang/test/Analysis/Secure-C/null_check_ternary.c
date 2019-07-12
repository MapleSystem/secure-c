// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stddef.h>
#include <secure_c.h>

int foo(int *x, int *y) __attribute__((secure_c_in(y, nonnull))) {
    return ( (x != NULL) ? (*x > 0) : (*y == 0) );
}
