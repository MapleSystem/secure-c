#include <stddef.h>
#include <assert.h>

int foo(int *f) {
  assert(f != NULL);
  return *f + 1;
}
