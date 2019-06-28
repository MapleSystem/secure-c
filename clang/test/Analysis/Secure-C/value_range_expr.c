// RUN: %clang -cc1 -analyze -analyzer-checker=secure-c.ValueRange -verify %s
int get(int *arr, unsigned int length, unsigned int idx)
    __attribute__((value_range(idx, 0, length - 1))) {
  return arr[idx];
}

int testWarn(int x) {
  int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  return get(arr, 10, x); // expected-warning {{Argument may not satisfy value_range constraints}}
}

char testError() {
  int arr[10] = {0, 1, 2, 3, 4, 5, 6};
  return get(arr, 7, 9); // expected-warning {{Argument does not satisfy value_range constraints}}
}

char testSafe(int flag) {
  int arr[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  int x = 0;
  if (flag)
    x = 5;
  return get(arr, 8, x);
}

char testUnsafe(int flag) {
  int arr[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  int x = 0;
  if (flag)
    x = 8;
  return get(arr, 8, x); // expected-warning {{Argument may not satisfy value_range constraints}}
}
