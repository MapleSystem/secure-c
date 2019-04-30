//bats @test "cast_struct_type.c: Casting a pointer to change nullabilty of its contents" {
//bats   run secure-c cast_struct_type.c --
//bats   [ $status != 0 ]
//bats }
#include <stddef.h>

struct NullableStruct {
  int *_Nullable p;
};

struct NonnullStruct {
  int *_Nonnull p;
};

int read_struct(struct NullableStruct *_Nonnull p) {
  struct NonnullStruct *_Nonnull q = (struct NonnullStruct *_Nonnull)p;
  return *q->p;          // Unsafe: field p may contain a null pointer
}
