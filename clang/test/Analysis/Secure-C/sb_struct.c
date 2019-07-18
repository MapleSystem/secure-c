// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
#include <secure_c.h>

// Larger than char[10]
struct S {
  char info[2];
  long a, b;
  char tag[2];
};

// Smaller than char[10]
struct A {
  char info[2];
  short s;
};

void f(char *_Nonnull buf) __attribute__((secure_c_in(buf, secure_buffer(10))));

void bar() {
  char array[12];
  char array2d[3][12];
  struct S s;
  struct A a;
  f(&array[0]);
  f(array2d[0]);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  f(a.info);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  f(&array[3]);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  f(&array2d[1][3]);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  f(s.info);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  f(s.tag);
}
