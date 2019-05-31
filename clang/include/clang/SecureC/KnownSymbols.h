#ifndef KNOWNSYMBOLS_H
#define KNOWNSYMBOLS_H

#include "clang/AST/AST.h"
#include "clang/Basic/Specifiers.h"
#include "llvm/ADT/StringRef.h"

using namespace clang;

class FuncNullability {
public:
  // For functions with no return value
  FuncNullability(std::initializer_list<NullabilityKind> PKs) {
    for (NullabilityKind kind : PKs) {
      ParamKinds.push_back(kind);
    }
  }

  // For functions with both return value and parameters
  FuncNullability(NullabilityKind RK,
                  std::initializer_list<NullabilityKind> PKs = {})
      : ReturnKind(RK) {
    for (NullabilityKind kind : PKs) {
      ParamKinds.push_back(kind);
    }
  }

  NullabilityKind ReturnKind;
  std::vector<NullabilityKind> ParamKinds;
};

class KnownSymbols {
public:
  KnownSymbols();
  bool isKnownFunction(const FunctionDecl *FD);
  bool isKnownNonNull(const Expr *E);
  bool isNonNullParam(const FunctionDecl *FD, int i);

private:
  std::map<StringRef, FuncNullability> KnownFuncs;
  std::map<StringRef, NullabilityKind> KnownDecls;

  void initializeKnownDecls();
  void initializeKnownFuncs();
};

#endif // KNOWNSYMBOLS_H
