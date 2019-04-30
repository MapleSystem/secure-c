//bats @test "memcpy_2.c: Using memcpy to copy a _Nonnull pointer safely" {
//bats   run secure-c memcpy_2.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>
#include <string.h>

void foo(int *_Nonnull *_Nonnull p, int *_Nonnull *_Nonnull q) {
  memcpy(p, q, sizeof(int *)); // Safe: both pointers have same type
}
