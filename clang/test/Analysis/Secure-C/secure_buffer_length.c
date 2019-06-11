// RUN: clang -fsyntax-only -Xclang -analyze -Xclang -analyzer-config -Xclang ipa=none -Xclang -analyzer-checker=unix.DynamicMemoryModeling -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
#include<stdlib.h>

int get(int *_Nonnull buf) __attribute__((secure_buffer(buf, 10)));

int foo(int w, int x, int y, int z)
    __attribute__((value_range(x, 10, 20),
                   value_range(y, 5, 7),
                   value_range(z, 5, 20))) {
  int A[10] = {0};
  get(A);

  int B[20] = {0};
  get(B);

  int C[5] = {0};
  get(C); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}

  int *D = malloc(sizeof(int) * 10);
  get(D);

  int *E = malloc(sizeof(int) * 3);
  get(E); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}

  int *F = malloc(sizeof(int) * w);
  get(F); // expected-warning {{Buffer argument may not satisfy secure_buffer constraint}}

  int *G = malloc(sizeof(int) * x);
  get(G);

  int *H = malloc(sizeof(int) * y);
  get(H); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}

  int *I = malloc(sizeof(int) * z);
  get(I); // expected-warning {{Buffer argument may not satisfy secure_buffer constraint}}

  int *J = A;
  get(J);

  int *K = B;
  get(K);

  int *L = C;
  get(L); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}

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

void f(char *_Nonnull buf) __attribute__((secure_buffer(buf, 10)));

int bar() {
  char array[12];
  char array2d[3][12];
  struct S s;
  struct A a;
  f(&array[0]);
  f(array2d[0]);
  f(a.info); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}
  f(&array[3]); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}
  f(&array2d[1][3]); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}
  f(s.info); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}
  f(s.tag); // expected-warning {{Buffer argument does not satisfy secure_buffer constraint}}
  return 0;
}
