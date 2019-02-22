//bats @test "unannotated.c: Pointer type function parameters must be annotated" {
//bats   run secure-c unannotated.c --
//bats   [[ ${lines[0]} =~ "9:10: error: pointer parameter is not annotated with either '_Nonnull' or '_Nullable'" ]]
//bats   [[ ${lines[3]} =~ "11:16: error: pointer parameter is not annotated with either '_Nonnull' or '_Nullable'" ]]
//bats   [ $status = 1 ]
//bats }
#include <stddef.h>

void foo(int *i);

int bar(int a, int *b) {
  if (b == NULL) {
    return a;
  }
  return 0;
}
