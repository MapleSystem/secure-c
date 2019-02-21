typedef struct {
  int count;
  int val;
} foo;

int get_count(foo * _Nullable f) {
  return f->count;
}
