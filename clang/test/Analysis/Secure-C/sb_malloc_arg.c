// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
#include <secure_c.h>
#include <stdlib.h>

int get(int *_Nonnull buf) __attribute__((secure_c_in(buf, secure_buffer(10))));

void foo(int w, int x, int y, int z)
    __attribute__((secure_c_in(x, value_range(10, 20)),
                   secure_c_in(y, value_range(5, 7)),
                   secure_c_in(z, value_range(5, 20)))) {
  int *D = malloc(sizeof(int) * 10);
  get(D);

  int *E = malloc(sizeof(int) * 3);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  get(E);
}
