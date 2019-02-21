#include <stddef.h>

void foo(int *i);

int bar(int a, int *b) {
  if (b == NULL) {
    return a;
  }
  return a + *b;
}
