// RUN: %clang -cc1 -analyze -analyzer-checker=secure-c.SecureCTaint -verify %s
void testUntrustIn(char *buf)
    __attribute__((
        secure_c_in(buf, "untrusted")));

void testUntrustOut(char *buf)
    __attribute__((
        secure_c_out(buf, "untrusted")));

void testTrustIn(char *buf)
    __attribute__((
        secure_c_in(buf, "trusted")));

void testTrustOut(char *buf)
    __attribute__((
        secure_c_out(buf, "trusted")));

void testUntrustInOut(char *buf)
    __attribute__((
        secure_c_in(buf, "untrusted"),
        secure_c_out(buf, "untrusted")));

void testUntrustInTrustOut(char *buf)
    __attribute__((
        secure_c_in(buf, "untrusted"),
        secure_c_out(buf, "trusted")));

void testTrustInUntrustOut(char *buf)
    __attribute__((
        secure_c_in(buf, "trusted"),
        secure_c_out(buf, "untrusted")));

void testTrustInOut(char *buf)
    __attribute__((
        secure_c_in(buf, "trusted"),
        secure_c_out(buf, "trusted")));

void testUntrustInMultiple(char *buf, int len)
    __attribute__((
        secure_c_in(buf, "untrusted"),
        secure_c_in(len, "untrusted")));

void testUntrustOutMultiple(char *buf, int len)
    __attribute__((
        secure_c_out(buf, "untrusted"),
        secure_c_out(len, "untrusted"))); // expected-error {{'secure_c_out' attribute requires parameter 1 to be a function parameter of pointer type}}

char *testUntrustReturn()
    __attribute__((
        secure_c_out(testUntrustReturn, "untrusted")));

char *testTrustReturn()
    __attribute__((
        secure_c_out(testTrustReturn, "trusted")));

char *testTrustReturnInvalidFuncName()
    __attribute__((
        secure_c_out(inValidFuncName, "trusted"))); // expected-error {{use of undeclared identifier 'inValidFuncName'}}

void testUntrustDataIn(char *buf)
    __attribute__((
        secure_c_in(*buf, "untrusted")));

void trustedInFunc(char *buf)
    __attribute__((
        secure_c_in(buf, "trusted")));

void untrustToTrustSanatizeFunc(char *buf)
    __attribute__((
        secure_c_in(buf, "untrusted"),
        secure_c_out(buf, "trusted")));

char *untrustToTrustReturnSanatizeFunc(char *buf)
    __attribute__((
        secure_c_in(buf, "untrusted"),
        secure_c_out(untrustToTrustReturnSanatizeFunc, "trusted")));

void untrustedOutFunc(char *buf)
    __attribute__((
        secure_c_out(buf, "untrusted")));

char *untrustedReturnFunc()
    __attribute__((
        secure_c_out(untrustedReturnFunc, "untrusted")));

void testUntrustPassedToTrust() {
  char *buf;
  buf = (char *)malloc(50);
  untrustedOutFunc(buf);
  trustedInFunc(buf); // expected-warning {{Untrusted data is passed to a trusted parameter in the call}}
}

void testUntrustPassedToTrust1() {
  char *buf;
  buf = untrustedReturnFunc();
  trustedInFunc(buf); // expected-warning {{Untrusted data is passed to a trusted parameter in the call}}
}

void testUntrustToTrustSanatize() {
  char *buf;
  buf = untrustedReturnFunc();
  untrustToTrustSanatizeFunc(buf);
  trustedInFunc(buf);
}

void testUntrustToTrustReturnSanatize() {
  char *buf;
  buf = untrustedReturnFunc();
  buf = untrustToTrustReturnSanatizeFunc(buf);
  trustedInFunc(buf);
}

void testUntrustedOutDereference() {
  char buf[50];
  untrustedOutFunc(buf);    // buf becomes untrusted
  printf("%c", buf[0]);     // expected-warning {{Possible null dereference or out-of-bound access due to untrusted array}}
  printf("%c", *(buf + 1)); // expected-warning {{Possibly a dangerous pointer arithmetic operation due to untrusted pointer}}
}

void testUntrustedOutArithmetic() {
  char *buf;
  buf = (char *)malloc(50);
  untrustedOutFunc(buf);
  buf = buf + 1;      // expected-warning {{Possibly a dangerous pointer arithmetic operation due to untrusted pointer}}
  buf++;              // expected-warning {{Possibly a dangerous pointer arithmetic operation due to untrusted pointer}}
  printf("%p", &buf); // expected-warning {{Possibly a dangerous AddressOf operation due to untrusted pointer variable}}
  printf("%c", *buf); // expected-warning {{Possible null or dangerous dereference due to untrusted pointer variable}}
}

void testUntrustedUseInCondition() {
  char c = getchar();
  if (c == '0') { // expected-warning {{Possible to take wrong branch or cause infinite/long loop due to untrusted variable in the branch/loop terminating condition}}

  } else {
  }

  int i = c;
  while (i-- > 0) {
  } // expected-warning {{Possible to take wrong branch or cause infinite/long loop due to untrusted variable in the branch/loop terminating condition}}
}

void testUntrustedSizeForMalloc() {
  int size = getchar();
  char *buf;
  buf = (char *)malloc(size); // expected-warning {{Untrusted data is used to specify the buffer size (CERT/STR31-C. Guarantee that storage for strings has sufficient space for character data and the null terminator)}}
}

void testUntrustedSizeForMalloc1() {
  int size;
  scanf("%d", &size);
  char *buf;
  buf = (char *)malloc(size); // expected-warning {{Untrusted data is used to specify the buffer size (CERT/STR31-C. Guarantee that storage for strings has sufficient space for character data and the null terminator)}}
}

void testUntrustedIntegerArithmetic() {
  int i, j;
  scanf("%d, %d", &i, &j);
  int k = i + j; // expected-warning {{Possible integer overflow due to untrusted operand variable}}
}

void bar(char *buf)
    __attribute__((
        secure_c_in(buf, "trusted")));

void foo(char *buf)
    __attribute__((
        secure_c_in(buf, "untrusted"))) {
  bar(buf); // expected-warning {{Untrusted data is passed to a trusted parameter in the call}}
}
int main() {
  char *buf;
  foo(buf);
  return 0;
}
