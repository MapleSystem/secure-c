//bats @test "deref_nonnull.c: Dereferencing a non-null pointer" {
//bats   run secure-c deref_nonnull.c --
//bats   [ $status = 0 ]
//bats }
int foo(int * _Nonnull x) {
  return *x;
}
