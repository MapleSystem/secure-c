int foo(unsigned int * _Nonnull x) {
  int *z = (int *)x;
  return z[4];
}

//bats @test "assign_nonnull.c: assign a non-null pointer" {
//bats run securify assign_nonnull.c --
//bats [ $status = 0 ]
//bats [[ ${lines[2]} =~ "int * _Nonnull z" ]]
//bats }
