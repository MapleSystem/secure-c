//bats @test "null_check_else.c: Accessing a nullable pointer in the else body of a null check" {
//bats   run secure-c null_check_else.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable x) {
  if (x == NULL) {
    return 0;
  } else {
    return *x;
  }
}
