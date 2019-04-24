#include <stddef.h>

struct Foo {
  unsigned int a;
};

int foo(void * _Nullable f) {
  if (f == NULL)
    return 0;

  if (((struct Foo *)f)->a > 0)
    return 1;

  return -1;
}

//bats @test "cast_access.c: Cast then access pointer" {
//bats   run secure-c cast_access.c --
//bats   [ $status = 0 ]
//bats }
