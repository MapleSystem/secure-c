//bats @test "call.c: Passing a non-null pointer to a non-null parameter" {
//bats   run secure-c call.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

void foo(int * _Nonnull ptr);

int gX;

void bar() {
  int * _Nonnull x = &gX;
  foo(x);
}
