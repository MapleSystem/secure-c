// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// This test is expected to fail until #183 and #135 are implemented
// XFAIL: *
#include <secure_c.h>
#include <string.h>

void foo(int *_Nonnull *_Nonnull p, int *_Nullable *_Nonnull q)
    __attribute__((secure_c_in(p, nonnull),
                   secure_c_in(*p, nonnull),
                   secure_c_in(q, nonnull))) {
  // expected-warning@+1 {{unsafe promotion from nullable pointer}}
  memcpy(p, q, sizeof(int *));
}
