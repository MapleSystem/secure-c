struct Foo {
  unsigned int a;
};

int foo(void *f) {
  if (((struct Foo *)f)->a > 0)
    return 1;
  return -1;
}

//bats @test "cast_access.c: Cast then access pointer" {
//bats   run securify cast_access.c --
//bats   [ $status = 0 ]
//bats   [[ ${lines[4]} =~ "void * _Nonnull f" ]]
//bats }
