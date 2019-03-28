//bats @test "warn_redundant.c: warn about redundant null-check" {
//bats run secure-c -check-redundant warn_redundant.c --
//bats [ $status = 0 ] && echo ${lines[0]}
//bats [[ ${lines[0]} =~ "warn_redundant.c:9:9: warning: possibly redundant null-check" ]]
//bats }
#include <stddef.h>

int foo(int * _Nonnull x) {
  if (x != NULL) {
    return *x;
  }
  return 0;
}
