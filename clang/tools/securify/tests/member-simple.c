struct A {
  int x;
  int y;
};

int foo(struct A *a) {
  return a->x + 1;
}
