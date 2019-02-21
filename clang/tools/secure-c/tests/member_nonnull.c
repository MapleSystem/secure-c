typedef struct {
  int count;
  int val;
} foo;

int get_count(foo * _Nonnull f) {
  return f->count;
}
