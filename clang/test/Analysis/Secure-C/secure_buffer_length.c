// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=unix.DynamicMemoryModeling \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange \
// RUN:   -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
#include <stdlib.h>
#include <secure_c.h>

int get(int *_Nonnull buf) __attribute__((secure_c_in(buf, secure_buffer(10))));

int foo(int w, int x, int y, int z)
    __attribute__((secure_c_in(x, value_range(10, 20)),
                   secure_c_in(y, value_range(5, 7)),
                   secure_c_in(z, value_range(5, 20)))) {
  int A[10] = {0};
  get(A);

  int B[20] = {0};
  get(B);

  int C[5] = {0};
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  get(C);

  int *D = malloc(sizeof(int) * 10);
  get(D);

  int *E = malloc(sizeof(int) * 3);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  get(E);

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

  int *J = A;
  get(J);

  int *K = B;
  get(K);

  int *L = C;
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  get(L);

  return 0;
}

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

int bar() {
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
  return 0;
}

void baz(int *buf1, int *buf2, int *buf3, int *buf4, unsigned int length3,
         unsigned int length4)
    __attribute__((secure_c_in(buf1, secure_buffer(10)),
                   secure_c_in(buf2, secure_buffer(9)),
                   secure_c_in(buf3, secure_buffer(length3)),
                   secure_c_in(length3, value_range(10, 20)),
                   secure_c_in(buf4, secure_buffer(length4)),
                   secure_c_in(length4, value_range(0, 9)))) {
  get(buf1);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  get(buf2);
  get(buf3);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  get(buf4);
}

int param_length_binop(int *_Nonnull buf, unsigned int x)
    __attribute__((secure_c_in(buf, secure_buffer(x * 2 + 1)),
                   secure_c_in(x, value_range(0, 100))));

int param_length_cast(int *_Nonnull buf, int length)
    __attribute__((secure_c_in(buf, secure_buffer((unsigned char)length))));

void complex_length_test() {
  int x[11];
  param_length_binop(x, 5);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  param_length_binop(x, 7);
  param_length_cast(x, 11);
  // expected-warning@+1 {{does not satisfy secure_buffer constraint}}
  param_length_cast(x, 12);
}
