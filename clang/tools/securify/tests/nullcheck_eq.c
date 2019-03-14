//bats @test "nullcheck_eq.c: if pointer equals NULL" {
//bats run securify nullcheck_eq.c --
//bats [ $status = 0 ]
//bats [[ ${lines[7]} =~ "int * _Nullable f" ]]
//bats }
#include <stddef.h>

int foo(int *f) {
  if (f == NULL) {
    return 0;
  }
  return *f + 1;
}
