//bats @test "return_value.c: annotate pointer return types" {
//bats run securify return_value.c --
//bats [ $status = 0 ]
//bats [[ ${lines[12]} =~ "int * _Nonnull foo" ]]
//bats [[ ${lines[16]} =~ "int * _Nullable bar" ]]
//bats [[ ${lines[24]} =~ "int * _Nullable baz" ]]
//bats [[ ${lines[31]} =~ "int * _Nonnull qux" ]]
//bats [[ ${lines[32]} =~ "int * _Nonnull qux" ]]
//bats }
#include <stddef.h>

int *foo(int * _Nonnull a) {
  return a;
}

int *bar(int * _Nonnull a, int flag) {
  if (flag != 0) {
    return a;
  }
  return NULL;
}

int g;
int *baz(int * _Nullable a, int flag) {
  if (flag != 0) {
    return a;
  }
  return &g;
}

int *qux(int * _Nonnull a);
int *qux(int * _Nonnull a) {
  return a;
}
