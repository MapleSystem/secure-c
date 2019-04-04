//bats @test "deref_nonnull.c: Dereferencing a non-null pointer" {
//bats   run secure-c deref_nonnull.c --
//bats   [ $status = 0 ]
//bats }

int foo(int * _Nonnull x) {
  return *x;
}

//bats @test "deref_nonnull.c: Statistics: dereferencing a non-null pointer" {
//bats   run secure-c -dump-stats deref_nonnull.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[4]} =~ "Dereferences:    1"$ ]]
//bats   [[ ${lines[8]} =~ "Total pointer uses: 1"$ ]]
//bats   [[ ${lines[10]} =~ "Safe by annotation: 1"$ ]]
//bats }
