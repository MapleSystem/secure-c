//bats @test "const_size_array.c: assign const_size_array to nonnull" {
//bats   run secure-c const_size_array.c --
//bats   [ $status = 0 ]
//bats }
void foo1(int * _Nonnull ptr);
void foo2(char * _Nonnull ptr);

int bar() {
  int ary[10];
  foo1(ary);
  foo2("hello");
  char * _Nonnull p2 = "world";
  return 0;
}
