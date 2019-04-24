int *foo_n_n(int * _Nullable * _Nullable p) {
  return *p;
}

int foo_n_nn(int * _Nullable * _Nonnull p) {
  return **p;
}

//bats @test "pointer_pointer_err.c: Accessing a pointer to a pointer (nullable)" {
//bats   run secure-c pointer_pointer_err.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":2:10: error: illegal access of nullable pointer type 'int * _Nullable * _Nullable'" ]]
//bats   [[ ${lines[3]} =~ ":6:10: error: illegal access of nullable pointer type 'int * _Nullable'" ]]
//bats }
