//bats @test "null_check_if.c: Accessing a nullable pointer in the then body of a null check" {
//bats   run secure-c null_check_if.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable x) {
  if (x != NULL) {
    return *x;
  }
  return 0;
}
