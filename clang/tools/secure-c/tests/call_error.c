#include <stddef.h>

void foo(int * _Nonnull ptr);

int bar() {
  int *x = NULL;
  foo(x);
  return *x;
}
