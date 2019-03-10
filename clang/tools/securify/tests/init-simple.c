int g;

int foo(int x) {
  int *f = &g;
  return *f + x;
}
