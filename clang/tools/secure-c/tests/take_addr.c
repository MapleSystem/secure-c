void foo(int * _Nonnull ptr);

int bar() {
  int x;
  foo(&x);
  return x;
}
