// RUN: %clang -fsyntax-only -I %S/../../../tools/secure-c/ \
// RUN:   -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.ValueRange -Xclang -verify %s
#include <secure_c.h>

char getLetter(int charIdx)
    __attribute__((secure_c_in(charIdx, value_range(0, 25)))) {
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
