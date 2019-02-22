//bats @test "null_check_and.c: Accessing a pointer after a null check" {
//bats   run secure-c null_check_and.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable a, int b) {
  if (a != NULL && b > 0) {
    return *a + b;
  }
  return b;
}