//bats @test "assign_null.c: assign NULL" {
//bats run securify assign_null.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int * _Nullable x" ]]
//bats }
#include <stddef.h>

int foo(int * _Nonnull a, int flag) {
  int *x = a;
  if (flag > 0) {
    x = NULL;
  }
  return *x;
}
