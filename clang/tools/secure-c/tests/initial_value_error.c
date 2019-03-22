//bats @test "initial_value_error.c: Initialize a non-null pointer to NULL" {
//bats   run secure-c initial_value_error.c --
//bats   [ $status = 1 ]
//bats }
#include <stddef.h>

int foo() {
  int * _Nonnull p = NULL;
  return *p;
}
