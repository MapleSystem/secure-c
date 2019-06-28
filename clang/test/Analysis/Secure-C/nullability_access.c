// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
#include <secure_c.h>
#include <stddef.h>

void deref_nullable(int *x) {
  int a = *x; // expected-warning {{illegal access of nullable pointer}}
  int *y = x;
  a = *y; // expected-warning {{illegal access of nullable pointer}}
}

void deref_nonnull(int *x) __attribute__((secure_c_in(x, nonnull))) {
  int a = *x;
  int *y = x;
  a = *y;
}

void deref_nullable_if_not_null(int *x, int y) {
  if (x != NULL) {
    int a = *x;
    int *y = x;
    a = *y;
  } else {
    int a = *x; // expected-warning {{illegal access of nullable pointer}}
  }
  int a = *x; // expected-warning {{illegal access of nullable pointer}}

  if (x != NULL && y > 0) {
    int a = *x + y;
  }
}

void deref_nullable_if_return(int *x) {
  if (!x)
    return;
  int a = *x;
}

void deref_nullable_if_null(int *x) {
  if (x == NULL) {
    int a = *x; // expected-warning {{illegal access of nullable pointer}}
  } else {
    int a = *x;
    int *y = x;
    a = *y;
  }
  int a = *x; // expected-warning {{illegal access of nullable pointer}}
}

void deref_nullable_if(int *x) {
  if (x) {
    int a = *x;
    int *y = x;
    a = *y;
  } else {
    int a = *x; // expected-warning {{illegal access of nullable pointer}}
  }
}

void deref_nullable_if_not(int *x) {
  if (!x) {
    int a = *x; // expected-warning {{illegal access of nullable pointer}}
  } else {
    int a = *x;
    int *y = x;
    a = *y;
  }
}

void deref_nullable_ternary(int *x, int *y, int z)
    __attribute__((secure_c_in(y, nonnull))) {
  int a = x ? *x : 0;
  int b = x ? 0 : *x; // expected-warning {{illegal access of nullable pointer}}
  a = (x != NULL) ? *x : 0;
  b = (x != NULL) ? 0 : *x; // expected-warning {{illegal access of nullable pointer}}
  a = (x == NULL) ? 0 : *x;
  b = (x == NULL) ? *x : 0; // expected-warning {{illegal access of nullable pointer}}
  a = *(z ? y : y);
  b = *(z ? x : y); // expected-warning {{illegal access of nullable pointer}}
  a = *(x ? x : y);
  b = *(x ? y : x); // expected-warning {{illegal access of nullable pointer}}
}

void deref_nullable_shortcut(int *x) {
  if (x && *x > 0)
    return;
  if (!x && *x > 0) // expected-warning {{illegal access of nullable pointer}}
    return;
  if (x || *x > 0) // expected-warning {{illegal access of nullable pointer}}
    return;
}

int null_check_or(int *a, int *b) {
  if (a == NULL || b == NULL) {
    return 0;
  } else {
    return *a + *b;
  }
}

int null_check_or_error(int *a, int b) {
  if (a != NULL || b > 0) {
    return *a + b; // expected-warning {{illegal access of nullable pointer}}
  }
  return b;
}

int null_check_and(int *a, int *b) {
  if (a != NULL && b != NULL) {
    return *a + *b;
  } else {
    return 0;
  }
}

int null_check_and_error(int *a, int *b) {
  if (a == NULL && b == NULL) {
    return 0;
  } else {
    return *a + *b; // expected-warning 2 {{illegal access of nullable pointer}}
  }
}

typedef struct foo {
  int *count;
  struct foo *ptr;
} foo;

void deref_nullable_field(foo *f) __attribute__((secure_c_in(f, nonnull))) {
  int a = *(f->count);
  // expected-warning@-1 {{illegal access of nullable pointer}}
}

void deref_nonnull_field(foo *f)
    __attribute__((secure_c_in(f, nonnull), secure_c_in(f->count, nonnull))) {
  int a = *(f->count);
}

void deref_nullable_field_field(foo *f)
    __attribute__((secure_c_in(f, nonnull), secure_c_in(f->ptr, nonnull))) {
  int a = *(f->ptr->count);
  // expected-warning@-1 {{illegal access of nullable pointer}}
}

void deref_nonnull_field_field(foo *f)
    __attribute__((secure_c_in(f, nonnull), secure_c_in(f->ptr, nonnull),
                   secure_c_in(f->ptr->count, nonnull))) {
  int a = *(f->ptr->count);
}

void access_nullable(foo *f) {
  int *a = f->count; // expected-warning {{illegal access of nullable pointer}}
}

void access_nonnull(foo *f) __attribute__((secure_c_in(f, nonnull))) {
  int *a = f->count;
}

void array_indexing_nullable(char *in) {
  char c = in[0]; // expected-warning {{illegal access of nullable pointer}}
}

void array_indexing_nonnull(char *in)
    __attribute__((secure_c_in(in, nonnull))) {
  char *data = "abcde";
  char c = in[0];
  c = data[0];
}

void func_ptr_nullable(void (*funcPtr)(void)) {
  funcPtr(); // expected-warning {{illegal access of nullable pointer}}
}

void func_ptr_nonnull(void (*funcPtr)(void))
    __attribute__((secure_c_in(funcPtr, nonnull))) {
  funcPtr();
}

struct List {
  struct List *next;
  int value;
};

unsigned int access_loop_check(struct List *l) {
  unsigned int length = 0;
  for (; l != NULL; l = l->next, length++)
    ;
  return length;
}

struct {
  int (*f)();
} g;

int member_call_nullable() {
  return g.f(); // expected-warning {{illegal access of nullable pointer}}
}

int member_call_nonnull() __attribute__((secure_c_in(g.f, nonnull))) {
  return g.f();
}

int multi_if(int *a, int *b) {
  if (!a)
    return 0;
  if (!b)
    return 1;
  return *a + *b;
}

int nested_if(int *a, int *b) {
  if (a != 0) {
    if (b != 0) {
      *a = *b;
      return 0;
    }
    *a = 1;
    return 1;
  }
  return 2;
}

int nested_if_error(int *p, int *q) {
  if (p != 0) {
    if (q != 0) {
      return 0;
    }
    *p = *q; // expected-warning {{illegal access of nullable pointer}}
  }
  return 0;
}

_Noreturn int panic(int err) { exit(err); }

int no_return(int *x) {
  if (x == NULL)
    panic(1);

  return *x;
}
