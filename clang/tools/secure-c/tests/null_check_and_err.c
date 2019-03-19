//bats @test "null_check_and_err.c: Accessing a pointer after an uncertain null check should report an error" {
//bats   run secure-c null_check_and_err.c --
//bats   [[ ${lines[0]} =~ ":13:12: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats   [[ ${lines[3]} =~ ":13:17: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats   [ $status = 1 ]
//bats }
#include <stddef.h>

int foo(int * _Nullable a, int * _Nullable b) {
  if (a == NULL && b == NULL) {
    return 0;
  } else {
    return *a + *b;
  }
}