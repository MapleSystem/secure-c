int foo_nn_nn(int * _Nonnull * _Nonnull p) {
  return **p;
}

//bats @test "pointer_pointer.c: Accessing a pointer to a pointer" {
//bats   run secure-c pointer_pointer.c --
//bats   [ $status = 0 ]
//bats }
