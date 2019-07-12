// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
// expected-no-diagnostics
#include <stdio.h>

void foo() {
  int *data;
  int tmp = 5;
  data = &tmp;
  printf("%d", *data);

  int **p2;
  p2 = &data;
  printf("%d", **p2);
}
