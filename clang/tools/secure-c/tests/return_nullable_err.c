//bats @test "return_nullable_err.c: Return _Nullable where _Nonnull is expected" {
//bats   skip "Skip until #137 is solved"
//bats   run secure-c return_nullable_err.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>

int *_Nonnull foo(int *_Nullable p) {
  return p;
}
