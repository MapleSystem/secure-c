//bats @test "null_check_ternary_right.c: Accessing a pointer in a ternary expression guarded by a check" {
//bats   run secure-c null_check_ternary_right.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable a, int b) {
  return (a == NULL) ? b : *a;
}
