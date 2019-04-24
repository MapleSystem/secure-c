#include <stdio.h>
#include <stdlib.h>

int get(int idx, int *_Nullable buf, int len)
    __attribute__((secure_buffer(buf, len))) {
  return 0;
}

int main() {
  // Dynamic array
  int *BPtr = (int *) malloc(sizeof(int) * 10);
  printf("%d\n", get(0, BPtr, 10));

  return 0;
}

//bats @test "sb_len_check_dynamic_valid.c: Valid length passed for secure buffer" {
//bats   run secure-c sb_len_check_dynamic_valid.c --
//bats   [ $status = 0 ]
//bats }