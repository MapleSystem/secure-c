#include <stdio.h>
#include<stdlib.h>

int get(int idx, int *_Nullable buf, int len)
    __attribute__((secure_buffer(buf, len))) {
  return 0;
}

int main() {
  // Dynamic array
  int *BPtr = (int *) malloc(sizeof(int) * 10);
  printf("%d\n", get(0, BPtr, 11));

  return 0;
}

//bats @test "sb_len_check_dynamic_invalid.c: Invalid length passed for secure buffer" { 
//bats   run secure-c sb_len_check_dynamic_invalid.c -- 
//bats   [ $status = 1 ]  
//bats   [[ ${lines[0]} =~ ":12:31: error: 11 is an invalid length for BPtr (length 10)" ]]  
//bats }