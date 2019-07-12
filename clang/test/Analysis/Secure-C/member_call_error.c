// RUN: %clang -fsyntax-only -I%S/../../../tools/secure-c -Xclang -analyze \
// RUN:   -Xclang -analyzer-config -Xclang ipa=none \
// RUN:   -Xclang -analyzer-checker=secure-c.Nullability -Xclang -verify %s
struct {
  int (*f)();
} g;

int foo() {
  return g.f(); // expected-warning {{illegal access of nullable pointer}}
}

//bats @test "member_call_error.c: Call from nullable member function pointer" {
//bats   run secure-c member_call_error.c --
//bats   [ $status = 1 ]
//bats   [[ ${lines[0]} =~ ":6:10: error: illegal access of nullable pointer type 'int (*)()'" ]]
//bats }
