//bats @test "cg_order_split[12].c: call-graph order dependent analysis, separate source files" {
//bats cp cg_order_split.h cg_order_split.h.orig
//bats cp cg_order_split2.c cg_order_split2.c.orig
//bats securify -overwrite cg_order_split2.c -- -include cg_order_split.h
//bats run securify cg_order_split1.c --
//bats mv cg_order_split.h.orig cg_order_split.h
//bats mv cg_order_split2.c.orig cg_order_split2.c
//bats [ $status = 0 ]
//bats [[ ${lines[13]} =~ "bar(int * _Nonnull x)" ]]
//bats }
#include "cg_order_split.h"

int bar(int *x) {
  return foo(x);
}
