//bats @test "loop_null_check.c: Null check in loop exit condition" {
//bats   run secure-c loop_null_check.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

struct List {
  struct List * _Nullable next;
  int value;
};

unsigned int List_length(struct List * _Nullable l) {
  unsigned int length = 0;
  for (; l != NULL; l = l->next, length++); // Safe: null check dominates `l->next`
  return length;
}
