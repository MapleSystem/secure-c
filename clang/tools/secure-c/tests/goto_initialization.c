//bats @test "goto_initialization.c: goto statement skips nonnull pointer initialization" {
//bats   run secure-c goto_initialization.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>

int foo(int * _Nonnull p) {
  goto skip_init;
  int *_Nonnull q = p;
 skip_init:
  return *q;                    // Unsafe: q has not been initialized
}
