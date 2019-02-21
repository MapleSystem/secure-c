#include <stddef.h>

int gX, gY;

int foo() {
  int * _Nonnull a = &gX;
  int * _Nonnull b = &gY;
  a = b;
  return 0;
}
