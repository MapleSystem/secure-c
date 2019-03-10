#include <stddef.h>

int foo(int *f) {
  if (f != NULL) {
    return *f + 1;
  }
  return 0;
}
