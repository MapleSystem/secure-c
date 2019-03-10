#include <stddef.h>

int foo(int * _Nullable f) {
  if (f != NULL) {
    return *f + 1;
  }
  return 0;
}
