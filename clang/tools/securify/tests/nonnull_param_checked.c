//bats @test "nonnull_param_checked.c: null-checked, then passed to non-null parameter" {
//bats run securify nonnull_param_checked.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int * _Nullable x" ]]
//bats }
#include <stddef.h>

int foo(int * _Nonnull f);

int bar(int *x) {
  if (x != NULL) {
    return foo(x);
  }
  return 0;
}
