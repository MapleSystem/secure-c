#include <stddef.h>
#include <stdlib.h>

_Noreturn int panic(int err) {
  exit(err);
}

int foo(int * _Nullable x) {
  if (x == NULL)
    panic(1);

  return *x;
}

//bats @test "noreturn.c: Use '_Noreturn' specifier" {
//bats   skip "Skip until #98 is fixed"
//bats   run secure-c noreturn.c --
//bats   [ $status = 0 ]
//bats }
