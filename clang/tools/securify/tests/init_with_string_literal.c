//bats @test "init_with_string_literal.c: initialize with string literal" {
//bats run securify init_with_string_literal.c --
//bats [ $status = 0 ]
//bats [[ ${lines[8]} =~ "char * _Nonnull x" ]]
//bats }
#include <stdio.h>

void foo(char * _Nonnull s) {
  char *x = s;
  printf("%c\n", x[0]);
}
