#include <stddef.h>

struct {
  int *f;
} g;

int foo() {
  if (g.f != NULL) {
    return *g.f;
  }
  return 0;
}

//bats @test "member_null_check.c: Access checked nullable member" {
//bats   skip "Skip until #86 is fixed"
//bats   run secure-c member_null_check.c --
//bats   [ $status = 0 ]
//bats }
