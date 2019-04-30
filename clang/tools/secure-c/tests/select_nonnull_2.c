//bats @test "select_nonnull_2.c: Conditional use of nonnull values is nonnull" {
//bats   run secure-c select_nonnull_2.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int foo(int *_Nullable p, int *_Nonnull q) {
  return *((p != NULL) ? p : q);
}
