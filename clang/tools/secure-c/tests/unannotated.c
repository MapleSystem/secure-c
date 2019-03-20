//bats @test "unannotated.c: Pointer type function parameters must be annotated" {
//bats   run secure-c unannotated.c --
//bats   [[ ${lines[0]} =~ "13:10: error: pointer parameter is not annotated with either '_Nonnull' or '_Nullable'" ]]
//bats   [[ ${lines[3]} =~ "15:16: error: pointer parameter is not annotated with either '_Nonnull' or '_Nullable'" ]]
//bats   [ $status = 1 ]
//bats }
//bats @test "unannotated.c: Default nullable with -default-nullable" {
//bats   run secure-c -default-nullable unannotated.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

void foo(int *i);

int bar(int a, int *b) {
  if (b == NULL) {
    return a;
  }
  return 0;
}
