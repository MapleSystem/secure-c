// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
// This test is expected to fail until #190 is resolved
// XFAIL: *
#include <secure_c.h>

int param_length_cast(int *_Nonnull buf, int length)
    __attribute__((secure_c_in(buf, secure_buffer((unsigned char)length))));

void cast_length_test() {
  int x[11];
  param_length_cast(x, 11);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  param_length_cast(x, 12);
}
