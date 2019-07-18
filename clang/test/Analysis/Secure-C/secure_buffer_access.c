// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
#include <secure_c.h>

int simple_safe() {
  int a[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  return a[4];
}

int simple_outside() {
  int a[3] = {0, 1, 2}; // expected-note {{array 'a' declared here}}
  return a[3];          // expected-warning {{Buffer access is out of bounds}} \
               // expected-warning {{array index 3 is past the end of the array}}
}

int safe(int *_Nonnull buf)
    __attribute__((secure_c_in(buf, secure_buffer(10)))) {
  return buf[9];
}

int outside(int *_Nonnull buf)
    __attribute__((secure_c_in(buf, secure_buffer(10)))) {
  return buf[10]; // expected-warning {{Buffer access is out of bounds}}
}

int unannotated(int *_Nonnull buf) {
  return buf[3]; // expected-warning {{Buffer access may be out of bounds}}
}

int unknown_range(int *_Nonnull buf, int idx)
    __attribute__((secure_c_in(buf, secure_buffer(10)))) {
  return buf[idx]; // expected-warning {{Buffer access may be out of bounds}}
}

int maybe_out_of_range(int *_Nonnull buf, int idx)
    __attribute__((secure_c_in(buf, secure_buffer(10)),
                   secure_c_in(idx, value_range(0, 10)))) {
  return buf[idx]; // expected-warning {{Buffer access may be out of bounds}}
}

int param_length_cast(int *_Nonnull buf, int length)
    __attribute__((secure_c_in(buf, secure_buffer((unsigned char)length)))) {
  return buf[0]; // expected-warning {{Buffer access may be out of bounds}}
}
