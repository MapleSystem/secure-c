// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
// This test is expected to fail until #188 is resolved
// XFAIL: *
#include <secure_c.h>

int safe_range(int *_Nonnull buf, int idx)
    __attribute__((secure_buffer(buf, 10), value_range(idx, 0, 9))) {
  return buf[idx];
}

int out_of_range(int *_Nonnull buf, int idx)
    __attribute__((secure_c_in(buf, secure_buffer(10)),
                   secure_c_in(idx, value_range(10, 20)))) {
  return buf[idx]; // expected-warning {{Buffer access is out of bounds}}
}
