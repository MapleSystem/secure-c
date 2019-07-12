// RUN: %clang -fsyntax-only -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
// This test is expected to fail until #159 is resolved
// XFAIL: *
#include <secure_c.h>

int get(int *buf) __attribute__((secure_c_in(buf, secure_buffer(10))));

void foo(int x, int y)
    __attribute__((secure_c_in(x, value_range(10, 20)),
                   secure_c_in(y, value_range(5, 7)))) {
  int *G = malloc(sizeof(int) * x);
  get(G);

  int *H = malloc(sizeof(int) * y);
  get(H); // expected-warning {{does not satisfy secure_buffer constraints}}
}
