//bats @test "goto_check.c: goto statement skips nonnull pointer check" {
//bats   run secure-c goto_check.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable p) {
  goto skip_check;
  if (p != NULL) {
  skip_check:
    return *p;                  // Unsafe: p may be null
  }
  return 0;
}
