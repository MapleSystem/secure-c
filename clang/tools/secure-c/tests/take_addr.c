//bats @test "take_addr.c: Passing an address to a non-null parameter" {
//bats   run secure-c take_addr.c --
//bats   [ $status = 0 ]
//bats }
void foo(int * _Nonnull ptr);

int bar() {
  int x;
  foo(&x);
  return x;
}
