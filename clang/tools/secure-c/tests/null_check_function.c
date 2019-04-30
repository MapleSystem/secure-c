//bats @test "null_check_function.c: Using a helper function to perform a null check" {
//bats   run secure-c null_check_function.c --
//bats   [ $status = 0 ]
//bats }
#include <stddef.h>

struct Foo {
  int tag;
};

int is_valid(struct Foo const *_Nullable a) {
  return a != NULL;
}

int get_tag(struct Foo *_Nullable p) {
  if (is_valid(p)) return p->tag;
  return 0;
}
