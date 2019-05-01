//bats @test "null_check_ternary_left_err.c: Accessing a pointer in a ternary expression guarded by an incorrect check" {
//bats   skip "Skip until #65 is solved"
//bats   run secure-c null_check_ternary_left_err.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable a, int b) {
  return (a != NULL) ? b : *a;
}
