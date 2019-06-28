// RUN: %clang -fsyntax-only -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
int test(int *buf, unsigned int length)
    __attribute__((secure_buffer(buf, length), value_range(length, 10, 20))) {
  int a = buf[5];
  int b = buf[10]; // expected-warning {{Buffer access may be out of bounds}}
  int c = buf[20]; // expected-warning {{Buffer access is out of bounds}}

  return a + b + c;
}
