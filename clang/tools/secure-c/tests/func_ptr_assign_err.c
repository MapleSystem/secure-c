//bats @test "func_ptr_assign_err.c: Assigning a function pointer" {
//bats   run secure-c func_ptr_assign_err.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":23:39: error: unsafe nullability mismatch in function pointer assignment" ]]
//bats   [[ ${lines[3]} =~ ":24:46: error: unsafe nullability mismatch in function pointer assignment" ]]
//bats }
#include <stddef.h>

int sink1(long * _Nonnull data) {
  return 42;
}

int sink2(long *  _Nullable data) {
  return 42;
}

long * _Nullable sink3(long *  _Nullable data) {
  return data;
}

void func() {
  long * data;
  int (*funcPtr) (long * _Nullable) = sink1;
  long * _Nonnull (*fp) (long * _Nullable) = sink3;
  funcPtr = sink2;
  data = NULL;
  funcPtr(data);
}
