#include <stddef.h>

int gX;

int foo() {
  int * _Nonnull a = &gX;
  int * b = NULL;
  a = b;
  return 0;
}
