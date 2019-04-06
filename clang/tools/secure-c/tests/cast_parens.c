int gX[32];

int foo(int x) {
  unsigned int * _Nonnull a = (unsigned int *)gX;
  a = (unsigned int *)(&(gX[x]));
  return *a;
}

//bats @test "cast_parens.c: Cast and parens around non-null expr" {
//bats   run secure-c cast_parens.c --
//bats   [ $status = 0 ]
//bats }
