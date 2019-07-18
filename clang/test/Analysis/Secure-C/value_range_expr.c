// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange -Xclang -verify %s
// This test is expected to fail until #191 is resolved
// XFAIL: *
#include <secure_c.h>

int get(int *arr, unsigned int length, unsigned int idx)
    __attribute__((secure_c_in(idx, value_range(0, length - 1)))) {
  return arr[idx];
}

int testWarn(int x) {
  int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  // expected-warning@+1 {{Argument may not satisfy value_range constraints}}
  return get(arr, 10, x);
}

char testError() {
  int arr[10] = {0, 1, 2, 3, 4, 5, 6};
  // expected-warning@+1 {{Argument does not satisfy value_range constraints}}
  return get(arr, 7, 9);
}

char testSafe(int flag) {
  int arr[8] = {0, 1, 2, 3, 4, 5, 6, 7};
  int x = 0;
  if (flag)
    x = 5;
  return get(arr, 8, x);
}
