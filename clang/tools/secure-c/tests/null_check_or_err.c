//bats @test "null_check_or_err.c: Accessing a pointer after an uncertain null check" {
//bats   run secure-c null_check_or_err.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":10:12: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats }
#include <stddef.h>

int foo(int * _Nullable a, int b) {
  if (a != NULL || b > 0) {
    return *a + b;
  }
  return b;
}
