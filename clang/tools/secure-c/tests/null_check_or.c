//bats @test "null_check_or.c: Accessing a pointer after a null check" {
//bats   run secure-c null_check_or.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable a, int * _Nullable b) {
  if (a == NULL || b == NULL) {
    return 0;
  } else {
    return *a + *b;
  }
}