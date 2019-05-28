// RUN:  clang -fsyntax-only -Xclang -analyze -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
#include<stdlib.h>

int get(int *_Nonnull buf) __attribute__((secure_buffer(buf, 10))) {
  return buf[9];
}

int foo(int w, int x, int y, int z)
    __attribute__((value_range(x, 10, 20),
                   value_range(y, 5, 7),
                   value_range(z, 5, 20))) {
  int A[10] = {0};
  get(A);

  int B[20] = {0};
  get(B);

  int C[5] = {0};
  get(C); // expected-warning {{Argument does not satisfy secure_buffer constraints}}

  int *D = malloc(sizeof(int) * 10);
  get(D);

  int *E = malloc(sizeof(int) * 3);
  get(E); // expected-warning {{Argument does not satisfy secure_buffer constraints}}

  int *F = malloc(sizeof(int) * x);
  get(F);

  int *G = malloc(sizeof(int) * y);
  get(G); // expected-warning {{Argument does not satisfy secure_buffer constraints}}

  int *H = malloc(sizeof(int) * x);
  get(H); // expected-warning {{Argument may not satisfy secure_buffer constraints}}

  int *I = A;
  get(I);

  int *J = B;
  get(J);

  int *K = C;
  get(K); // expected-warning {{Argument does not satisfy secure_buffer constraints}}

  return 0;
}
