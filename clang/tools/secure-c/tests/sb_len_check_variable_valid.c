#include <stdio.h>
int get(int idx, int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len))) {
  return 0;
}

int main() {
  // Variable size array
  const int x = 10;
  int VB[x];
  printf("%d\n", get(0, VB, x));

  return 0;
}

//bats @test "sb_len_check_variable_valid.c: Valid length passed for secure buffer" {
//bats   run secure-c sb_len_check_variable_valid.c --
//bats   [ $status = 0 ]
//bats }