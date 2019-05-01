//bats @test "memset_null_err.c: Setting a pointer value to null using memset" {
//bats   skip "Skip until #135 is solved"
//bats   run secure-c memset_null_err.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>
#include <string.h>

void foo(int *_Nonnull *_Nonnull p) {
  memset(p, 0, sizeof(int *)); // Unsafe: writes a null pointer value
}
