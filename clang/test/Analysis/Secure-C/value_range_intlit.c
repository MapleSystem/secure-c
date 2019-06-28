// RUN: %clang -cc1 -analyze -analyzer-checker=secure-c.ValueRange -verify %s
char getLetter(int charIdx) __attribute__((value_range(charIdx, 0, 25))) {
  return 'A' + charIdx;
}

char testWarn(int x) {
  return getLetter(x); // expected-warning {{Argument may not satisfy value_range constraints}}
}

char testError() {
  return getLetter(33); // expected-warning {{Argument does not satisfy value_range constraints}}
}

char testSafe(int flag) {
  int x = 0;
  if (flag)
    x = 10;
  return getLetter(x);
}
