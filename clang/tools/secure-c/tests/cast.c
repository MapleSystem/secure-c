//bats @test "cast.c: Assigning a non-null pointer to a non-null pointer" {
//bats   run secure-c cast.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int gX, gY;

int foo() {
  int * _Nonnull a = &gX;
  int * _Nonnull b = &gY;
  a = b;
  return 0;
}
