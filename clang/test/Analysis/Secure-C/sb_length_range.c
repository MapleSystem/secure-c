// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
// This test is expected to fail until #189 is resolved
// XFAIL: *
#include <secure_c.h>

int param_length(int *_Nonnull buf, unsigned int x)
    __attribute__((secure_c_in(buf, secure_buffer(x)),
                   secure_c_in(x, value_range(10, 100)))) {
  return buf[5];
}

int param_length_warn(int *_Nonnull buf, unsigned int x)
    __attribute__((secure_c_in(buf, secure_buffer(x)),
                   secure_c_in(x, value_range(5, 10)))) {
  return buf[5]; // expected-warning {{Buffer access may be out of bounds}}
}

int param_length_err(int *_Nonnull buf, unsigned int x)
    __attribute__((secure_c_in(buf, secure_buffer(x)),
                   secure_c_in(x, value_range(0, 5)))) {
  return buf[5]; // expected-warning {{Buffer access is out of bounds}}
}

int param_length_binop(int *_Nonnull buf, unsigned int x)
    __attribute__((secure_c_in(buf, secure_buffer(x + 10)),
                   secure_c_in(x, value_range(0, 5)))) {
  return buf[5];
}
