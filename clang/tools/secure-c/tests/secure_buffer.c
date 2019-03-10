#include <stdio.h>

int get(int flag, int *_Nonnull buf) __attribute__((secure_buffer(buf, 10))) {
  if (flag > 0)
    return buf[7];
  else if (flag < 0)
    return buf[3];
  else return buf[0];
}

int main() {
  int B[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  printf("%d\n", get(-22, B) + get(29, B));
  return 0;
}

// bats @test "secure_buffer.c: Simple use of secure_buffer annotation" {
// bats   run secure-c secure_buffer.c --
// bats   [ $status = 0 ]
// bats }
