#include <stdio.h>
int get(int idx, int *_Nonnull buf, int len)
    __attribute__((secure_buffer(buf, len))) {
  return 0;
}

int main() {
  // Static array
  int B[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  printf("%d\n", get(0, B, 11));

  return 0;
}

//bats @test "sb_len_check_static_invalid.c: Invalid length passed for secure buffer" { 
//bats   run secure-c sb_len_check_static_invalid.c -- 
//bats   [ $status = 1 ]  
//bats   [[ ${lines[0]} =~ ":10:28: error: 11 is an invalid length for B (length 10)" ]]  
//bats }