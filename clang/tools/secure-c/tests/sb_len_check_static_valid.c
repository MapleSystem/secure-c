#include <stdio.h>
int get(int idx, int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len))) {
  return 0;
}

int main() {
  // Static array
  int B[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  printf("%d\n", get(0, B, 10));

  return 0;
}

//bats @test "sb_len_check_static_valid.c: Valid length passed for secure buffer" {
//bats   run secure-c sb_len_check_static_valid.c --
//bats   [ $status = 0 ]
//bats }