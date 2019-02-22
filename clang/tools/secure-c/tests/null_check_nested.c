//bats @test "null_check_nested.c: Accessing a null-checked nullable pointer in a nested if" {
//bats   run secure-c null_check_nested.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int *_Nullable x, int b) {
  if (x != NULL) {
    if (b > 0) {
      return *x + b;
    }
  }
  return 0;
}
