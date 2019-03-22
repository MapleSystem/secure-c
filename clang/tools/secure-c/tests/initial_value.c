//bats @test "initial_value.c: Consider initial values in nullability analysis" {
//bats   run secure-c initial_value.c --
//bats   [ $status = 0 ]
//bats }
int foo() {
  int x = 4;
  int *p = &x;
  return *p;
}
