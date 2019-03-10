#include <stdio.h>

char getLetter(int charIdx) __attribute__((value_range(charIdx, 0, 25))) {
  return 'A' + charIdx;
}

int main() {
  char word[4];
  word[0] = getLetter(5);
  word[1] = getLetter(14);
  word[2] = getLetter(14);
  word[3] = '\0';

  printf("%s\n", word);
  return 0;
}

//bats @test "value_range.c: Simple use of value range annotation" {
//bats   run secure-c value_range.c --
//bats   [ $status = 0 ]
//bats }
