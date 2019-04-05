int foo(unsigned int * _Nonnull x) {
  int * _Nonnull z = (int *)x;
  return z[4];
}

//bats @test "assign_nonnull.c: assign a non-null pointer" {
//bats run secure-c assign_nonnull.c --
//bats [ $status = 0 ]
//bats }

