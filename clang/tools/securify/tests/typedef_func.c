typedef int (*DoSomething)(int,int*);
DoSomething foo(int*);

int bar(int a, int*b) {
  return a + *b;
}

int baz(int a, int*b) {
  return a * *b;
}

DoSomething foo(int *x) {
  if (*x > 0) {
    return bar;
  }
  return baz;
}

//bats @test "typedef_func.c: Insert annotation into func ptr typedef" {
//bats run securify typedef_func.c --
//bats [ $status = 0 ] && echo ${lines[9]}
//bats [[ ${lines[2]} =~ "DoSomething _Nonnull  foo(int* _Nonnull );" ]]
//bats [[ ${lines[9]} =~ "DoSomething _Nonnull  foo(int * _Nonnull x) {" ]]
//bats }
