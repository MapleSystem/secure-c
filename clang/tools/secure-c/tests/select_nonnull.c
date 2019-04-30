//bats @test "select_nonnull.c: Conditional use of nonnull values is nonnull" {
//bats   run secure-c select_nonnull.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int a, int *_Nonnull p, int *_Nonnull q) {
  return *(a ? p : q);
}
