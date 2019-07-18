// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
// This test is expected to fail until #159 is resolved
// XFAIL: *
#include <secure_c.h>
#include <stdlib.h>

int get(int *_Nonnull buf) __attribute__((secure_c_in(buf, secure_buffer(10))));

void foo(int w, int x, int y, int z)
    __attribute__((secure_c_in(x, value_range(10, 20)),
                   secure_c_in(y, value_range(5, 7)),
                   secure_c_in(z, value_range(5, 20)))) {
  int *F = malloc(sizeof(int) * w);
  // expected-warning@+1 {{may not satisfy secure_buffer constraint}}
  get(F);

  int *G = malloc(sizeof(int) * x);
  get(G);

  int *H = malloc(sizeof(int) * y);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  get(H);

  int *I = malloc(sizeof(int) * z);
  // expected-warning@+1 {{may not satisfy secure_buffer constraint}}
  get(I);
}
