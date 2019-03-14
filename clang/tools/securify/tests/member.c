//bats @test "member.c: unprotected member access" {
//bats run securify member.c --
//bats [ $status = 0 ]
//bats [[ ${lines[10]} =~ "struct A * _Nonnull a" ]]
//bats }
struct A {
  int x;
  int y;
};

int foo(struct A *a) {
  return a->x + 1;
}
