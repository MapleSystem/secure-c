//bats @test "null_check_return.c: Accessing a nullable pointer after a null check with a return" {
//bats   run secure-c null_check_return.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable x) {
  if (x == NULL) {
    return 0;
  }
  return *x;
}
