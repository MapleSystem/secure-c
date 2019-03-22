//bats @test "extern.c: Handle extern variables" {
//bats   run secure-c extern.c --
//bats   [ $status = 0 ]
//bats }
typedef struct{} FILE;
extern FILE * _Nonnull stdout;
int fprintf(FILE * _Nonnull stream, const char * _Nonnull format, ...);

void foo(void) {
  fprintf(stdout, "Hello, world!\n");
}
