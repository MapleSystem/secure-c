// RUN: clang -fsyntax-only -Xclang -analyze -Xclang -analyzer-config -Xclang ipa=none -Xclang -analyzer-checker=unix.DynamicMemoryModeling -Xclang -analyzer-checker=secure-c.SecureBuffer -Xclang -verify %s
int simple_safe() {
  int a[10] = {0,1,2,3,4,5,6,7,8,9};
  return a[4];
}

int simple_outside() {
  int a[3] = {0,1,2};
  return a[3]; // expected-warning {{Buffer access is out of bounds}}
}

int safe(int *_Nonnull buf) __attribute__((secure_buffer(buf, 10))) {
  return buf[9];
}

int outside(int *_Nonnull buf) __attribute__((secure_buffer(buf, 10))) {
  return buf[10]; // expected-warning {{Buffer access is out of bounds}}
}

int unannotated(int *_Nonnull buf) {
  return buf[3]; // expected-warning {{Buffer access may be out of bounds}}
}

int safe_range(int *_Nonnull buf, int idx)
    __attribute__((secure_buffer(buf, 10),
                   value_range(idx, 0, 9))) {
  return buf[idx];
}

int unknown_range(int *_Nonnull buf, int idx) __attribute__((secure_buffer(buf, 10))) {
  return buf[idx]; // expected-warning {{Buffer access may be out of bounds}}
}

int maybe_out_of_range(int *_Nonnull buf, int idx)
    __attribute__((secure_buffer(buf, 10),
                   value_range(idx, 0, 10))) {
  return buf[idx]; // expected-warning {{Buffer access may be out of bounds}}
}

int out_of_range(int *_Nonnull buf, int idx)
    __attribute__((secure_buffer(buf, 10),
                   value_range(idx, 10, 20))) {
  return buf[idx]; // expected-warning {{Buffer access is out of bounds}}
}
