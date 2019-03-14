//bats @test "init_then_check.c: initialize as non-null, later null-check" {
//bats run securify init_then_check.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int * _Nullable x" ]]
//bats }
#include <stddef.h>

int foo(int * _Nonnull a) {
  int *x = a;
  if (x == NULL) {
    return 0;
  }
  return *x;
}
