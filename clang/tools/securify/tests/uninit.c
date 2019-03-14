//bats @test "uninit.c: uninitialized" {
//bats run securify uninit.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int * _Nullable x" ]]
//bats }
#include <stddef.h>

int foo() {
  int *x;
  return *x;
}
