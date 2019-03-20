//bats @test "assert.c: assert pointer != NULL" {
//bats skip
//bats run securify assert.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "int * _Nonnull f" ]]
//bats }
#include <stddef.h>
#include <assert.h>

int foo(int *f) {
  assert(f != NULL);
  return *f + 1;
}
