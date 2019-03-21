//bats @test "multi_if_return.c: duducing nullness after multiple if and return statements" {
//bats   run secure-c multi_if_return.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

int * _Nullable bar();

int foo(int * _Nullable a) {
  int *b;
  if (a == NULL) return 0;

  b = bar();

  if (b == NULL) return 1;

  return *a + *b;
}