//bats @test "init_with_null.c: initialize with NULL" {
//bats run securify init_with_null.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int * _Nullable x" ]]
//bats }
#include <stddef.h>

int foo() {
  int *x = NULL;
  return *x;
}
