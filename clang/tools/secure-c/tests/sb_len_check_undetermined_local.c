#include <stdio.h>
int get(int idx, int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len))) {
  return 0;
}

int main() {
  // Static array
  int x = 10;
  int B[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  printf("%d\n", get(0, B, x));

  return 0;
}

//bats @test "sb_len_check_undetermined_local.c: Length not guaranteed to be valid for secure buffer" { 
//bats   run secure-c sb_len_check_undetermined_local.c -- 
//bats   [ $status = 1 ]  
//bats   [[ ${lines[0]} =~ ":11:28: error: x is not guaranteed to be a valid length for B" ]]  
//bats }