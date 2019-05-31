#include "clang/SecureC/KnownSymbols.h"

KnownSymbols::KnownSymbols() {
  initializeKnownDecls();
  initializeKnownFuncs();
}

void KnownSymbols::initializeKnownDecls() {
  KnownDecls.insert(std::pair<StringRef, NullabilityKind>(
      StringRef("stdin"), NullabilityKind::NonNull));
  KnownDecls.insert(std::pair<StringRef, NullabilityKind>(
      StringRef("stdout"), NullabilityKind::NonNull));
  KnownDecls.insert(std::pair<StringRef, NullabilityKind>(
      StringRef("stderr"), NullabilityKind::NonNull));
}

void KnownSymbols::initializeKnownFuncs() {
  // TODO: Could we use table-gen for this?
  // void *_Nullable malloc(size_t size);
  KnownFuncs.insert(std::make_pair(
      StringRef("malloc"), FuncNullability(NullabilityKind::Nullable,
                                           {NullabilityKind::Unspecified})));
  // void free(void *_Nonnull ptr);
  KnownFuncs.insert(std::make_pair(
      StringRef("free"), FuncNullability({NullabilityKind::NonNull})));
  // void *_Nullable calloc(size_t nmemb, size_t size);
  KnownFuncs.insert(std::make_pair(
      StringRef("calloc"), FuncNullability(NullabilityKind::Nullable,
                                           {NullabilityKind::Unspecified,
                                            NullabilityKind::Unspecified})));
  // void *_Nullable realloc(void *_Nullable ptr, size_t size);
  KnownFuncs.insert(std::make_pair(
      StringRef("realloc"), FuncNullability(NullabilityKind::Nullable,
                                            {NullabilityKind::Nullable,
                                             NullabilityKind::Unspecified})));
  // void *_Nullable reallocarray(void *_Nonnull ptr, size_t nmemb,
  //                              size_t size);
  KnownFuncs.insert(std::make_pair(
      StringRef("reallocarray"),
      FuncNullability(NullabilityKind::Nullable,
                      {NullabilityKind::NonNull, NullabilityKind::Unspecified,
                       NullabilityKind::Unspecified})));

  // int printf(const char *_Nonnull format, ...);
  KnownFuncs.insert(std::make_pair(
      StringRef("printf"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::NonNull})));
  // int fprintf(FILE *_Nonnull stream, const char *_Nonnull format, ...);
  KnownFuncs.insert(std::make_pair(
      StringRef("fprintf"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // int dprintf(int fd, const char *_Nonnull format, ...);
  KnownFuncs.insert(std::make_pair(
      StringRef("dprintf"), FuncNullability(NullabilityKind::Unspecified,
                                            {NullabilityKind::Unspecified,
                                             NullabilityKind::NonNull})));
  // int sprintf(char *_Nonnull str, const char *_Nonnull format, ...);
  KnownFuncs.insert(std::make_pair(
      StringRef("sprintf"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // int snprintf(char *_Nonnull str, size_t size,
  //              const char *_Nonnull format, ...);
  KnownFuncs.insert(std::make_pair(
      StringRef("snprintf"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::Unspecified,
                       NullabilityKind::NonNull})));
  // int vprintf(const char *_Nonnull format, va_list ap);
  KnownFuncs.insert(std::make_pair(
      StringRef("vprintf"), FuncNullability(NullabilityKind::Unspecified,
                                            {NullabilityKind::NonNull,
                                             NullabilityKind::Unspecified})));
  // int vfprintf(FILE *_Nonnull stream, const char *_Nonnull format,
  //              va_list ap);
  KnownFuncs.insert(std::make_pair(
      StringRef("vfprintf"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));
  // int vdprintf(int fd, const char *_Nonnull format, va_list ap);
  KnownFuncs.insert(std::make_pair(
      StringRef("vdprintf"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::Unspecified, NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));
  // int vsprintf(char *_Nonnull str, const char *_Nonnull format,
  //              va_list ap);
  KnownFuncs.insert(std::make_pair(
      StringRef("vsprintf"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));
  // int vsnprintf(char *_Nonnull str, size_t size,
  //               const char *_Nonnull format, va_list ap);
  KnownFuncs.insert(std::make_pair(
      StringRef("vsnprintf"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::Unspecified,
                       NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));

  // int open(const char *_Nonnull pathname, int flags, ...);
  KnownFuncs.insert(std::make_pair(
      StringRef("open"), FuncNullability(NullabilityKind::Unspecified,
                                         {NullabilityKind::NonNull,
                                          NullabilityKind::Unspecified})));
  // int creat(const char *_Nonnull pathname, mode_t mode);
  KnownFuncs.insert(std::make_pair(
      StringRef("creat"), FuncNullability(NullabilityKind::Unspecified,
                                          {NullabilityKind::NonNull,
                                           NullabilityKind::Unspecified})));
  // int openat(int dirfd, const char *_Nonnull pathname, int flags, ...);
  KnownFuncs.insert(std::make_pair(
      StringRef("openat"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::Unspecified, NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));
  // int stat(const char *_Nonnull pathname, struct stat *_Nonnull statbuf);
  KnownFuncs.insert(std::make_pair(
      StringRef("stat"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // int fstat(int fd, struct stat *_Nonnull statbuf);
  KnownFuncs.insert(std::make_pair(
      StringRef("fstat"), FuncNullability(NullabilityKind::Unspecified,
                                          {NullabilityKind::Unspecified,
                                           NullabilityKind::NonNull})));
  // int lstat(const char *_Nonnull pathname, struct stat *_Nonnull statbuf);
  KnownFuncs.insert(std::make_pair(
      StringRef("lstat"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // ssize_t read(int fd, void *_Nullable buf, size_t count);
  KnownFuncs.insert(std::make_pair(
      StringRef("read"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::Unspecified, NullabilityKind::Nullable,
                       NullabilityKind::Unspecified})));
  // ssize_t write(int fd, const void *_Nullable buf, size_t count);
  KnownFuncs.insert(std::make_pair(
      StringRef("write"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::Unspecified, NullabilityKind::Nullable,
                       NullabilityKind::Unspecified})));
  // FILE *_Nullable fopen(const char *_Nonnull pathname,
  //                       const char *_Nonnull mode);
  KnownFuncs.insert(std::make_pair(
      StringRef("fopen"),
      FuncNullability(NullabilityKind::Nullable,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // FILE *_Nullable fdopen(int fd, const char *_Nonnull mode);
  KnownFuncs.insert(std::make_pair(
      StringRef("fdopen"),
      FuncNullability(NullabilityKind::Nullable, {NullabilityKind::Unspecified,
                                                  NullabilityKind::NonNull})));
  // FILE *_Nullable freopen(const char *_Nonnull pathname,
  //                         const char *_Nonnull mode,
  //                         FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("freopen"),
      FuncNullability(NullabilityKind::Nullable,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull,
                       NullabilityKind::NonNull})));
  // int fclose(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("fclose"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::NonNull})));
  // size_t fread(void *_Nonnull ptr, size_t size, size_t nmemb,
  //              FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("fread"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::Unspecified,
                       NullabilityKind::Unspecified,
                       NullabilityKind::NonNull})));
  // size_t fwrite(const void *_Nonnull ptr, size_t size, size_t nmemb,
  //               FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("fwrite"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::Unspecified,
                       NullabilityKind::Unspecified,
                       NullabilityKind::NonNull})));
  // int fflush(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("fflush"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::NonNull})));

  // int fgetc(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("fgetc"), FuncNullability(NullabilityKind::Unspecified,
                                          {NullabilityKind::NonNull})));
  // char *_Nullable fgets(char *_Nonnull s, int size, FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("fgets"),
      FuncNullability(NullabilityKind::Nullable,
                      {NullabilityKind::NonNull, NullabilityKind::Unspecified,
                       NullabilityKind::NonNull})));
  // int getc(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("getc"), FuncNullability(NullabilityKind::Unspecified,
                                         {NullabilityKind::NonNull})));
  // int getchar(void);
  KnownFuncs.insert(std::make_pair(
      StringRef("getchar"), FuncNullability(NullabilityKind::Unspecified)));
  // int ungetc(int c, FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("ungetc"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::Unspecified,
                                            NullabilityKind::NonNull})));

  // void clearerr(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("clearerr"), FuncNullability({NullabilityKind::NonNull})));
  // int feof(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("feof"), FuncNullability(NullabilityKind::Unspecified,
                                         {NullabilityKind::NonNull})));
  // int ferror(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("ferror"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::NonNull})));
  // int fileno(FILE *_Nonnull stream);
  KnownFuncs.insert(std::make_pair(
      StringRef("fileno"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::NonNull})));

  // char *_Nonnull strcat(char *_Nonnull dest, const char *_Nonnull src);
  KnownFuncs.insert(std::make_pair(
      StringRef("strcat"),
      FuncNullability(NullabilityKind::NonNull,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // char *_Nonnull strncat(char *_Nonnull dest, const char *_Nonnull src,
  //                        size_t n);
  KnownFuncs.insert(std::make_pair(
      StringRef("strncat"),
      FuncNullability(NullabilityKind::NonNull,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));
  // size_t strlen(const char *_Nonnull s);
  KnownFuncs.insert(std::make_pair(
      StringRef("strlen"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::NonNull})));
  // int strcmp(const char *_Nonnull s1, const char *_Nonnull s2);
  KnownFuncs.insert(std::make_pair(
      StringRef("strcmp"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // int strncmp(const char *_Nonnull s1, const char *_Nonnull s2, size_t n);
  KnownFuncs.insert(std::make_pair(
      StringRef("strncmp"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));
  // char *_Nonnull strcpy(char *_Nonnull dest, const char *_Nonnull src);
  KnownFuncs.insert(std::make_pair(
      StringRef("strcpy"),
      FuncNullability(NullabilityKind::NonNull,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull})));
  // char *_Nonnull strncpy(char *_Nonnull dest, const char *_Nonnull src,
  //                        size_t n);
  KnownFuncs.insert(std::make_pair(
      StringRef("strncpy"),
      FuncNullability(NullabilityKind::NonNull,
                      {NullabilityKind::NonNull, NullabilityKind::NonNull,
                       NullabilityKind::Unspecified})));

  // FIXME: This current technique cannot handle pointers to pointers!
  // const unsigned short int *_Nonnull *_Nonnull __ctype_b_loc(void);
  KnownFuncs.insert(std::make_pair(StringRef("__ctype_b_loc"),
                                   FuncNullability(NullabilityKind::NonNull)));
  // const __int32_t *_Nonnull *_Nonnull __ctype_tolower_loc(void);
  KnownFuncs.insert(std::make_pair(StringRef("__ctype_tolower_loc"),
                                   FuncNullability(NullabilityKind::NonNull)));
  // const __int32_t *_Nonnull *_Nonnull __ctype_toupper_loc(void);
  KnownFuncs.insert(std::make_pair(StringRef("__ctype_toupper_loc"),
                                   FuncNullability(NullabilityKind::NonNull)));

  // int *_Nonnull __errno_location(void);
  KnownFuncs.insert(std::make_pair(StringRef("__errno_location"),
                                   FuncNullability(NullabilityKind::NonNull)));

  // int utime(const char *_Nonnull filename,
  //           const struct utimbuf *_Nullable times);
  KnownFuncs.insert(std::make_pair(
      StringRef("utime"),
      FuncNullability(NullabilityKind::Unspecified,
                      {NullabilityKind::NonNull, NullabilityKind::Nullable})));
  // int utimes(const char *_Nonnull filename, const struct timeval times[2]);
  KnownFuncs.insert(std::make_pair(
      StringRef("utimes"), FuncNullability(NullabilityKind::Unspecified,
                                           {NullabilityKind::NonNull,
                                            NullabilityKind::Unspecified})));

  // char *_Nullable getenv(const char *_Nonnull name);
  KnownFuncs.insert(std::make_pair(
      StringRef("getenv"),
      FuncNullability(NullabilityKind::Nullable, {NullabilityKind::NonNull})));
}

bool KnownSymbols::isKnownFunction(const FunctionDecl *FD) {
  return KnownFuncs.find(FD->getName()) != KnownFuncs.end();
}

bool KnownSymbols::isNonNullParam(const FunctionDecl *FD, int i) {
  if (isKnownFunction(FD))
    return KnownFuncs.find(FD->getName())->second.ParamKinds[i] ==
           NullabilityKind::NonNull;
  return false;
}

bool KnownSymbols::isKnownNonNull(const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      auto iter = KnownDecls.find(VD->getName());
      if (iter != KnownDecls.end()) {
        if (iter->second == NullabilityKind::NonNull)
          return true;
        else
          return false;
      }
    }
  }

  return false;
}
