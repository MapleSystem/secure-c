#include <stddef.h>

void foo(int * _Nonnull ptr);

int gX;

int bar() {
  int * _Nonnull x = &gX;
  foo(x);
  return *x;
}
