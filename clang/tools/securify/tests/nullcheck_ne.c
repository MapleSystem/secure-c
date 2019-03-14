//bats @test "nullcheck_ne.c: if test with != NULL" {
//bats run securify nullcheck_ne.c --
//bats [ $status = 0 ]
//bats [[ ${lines[7]} =~ "int * _Nullable f" ]]
//bats }
#include <stddef.h>

int foo(int *f) {
  if (f != NULL) {
    return *f + 1;
  }
  return 0;
}
