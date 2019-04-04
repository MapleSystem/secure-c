#ifndef NULLSCOPE_H
#define NULLSCOPE_H

#include <map>

#include "clang/AST/AST.h"

using namespace clang;

class NullScope {
  // Decls that have been checked (with if-stmt) in this scope.
  // true = known to be NULL, false = known to be non-NULL
  std::map<Decl *, bool> CheckedDecls;
  // Decls that are either assigned in this scope, or checked
  // in a child scope with early returns.
  std::map<Decl *, bool> localDecls;
  // Whether we are certain of CheckedDecls or not.
  // For example, uncertain for condition is "p == NULL || q == NULL".
  // Only matters when there are >1 decls in the scope.
  bool Certain;
  // whether the if-condition is compound (by OR/AND)
  bool Compound;
  // Whether we have seen a return statement in this scope
  bool Returned;

public:
  NullScope();
  void setCheckedNullability(Decl *D, bool isNull);
  void setLocalNullability(Decl *D, bool isNull);
  void cleanLocalNullability();
  void setUncertain(bool uncertain);
  bool isCertain();
  void setReturned();
  void setCompound();
  bool hasReturned();

  // Return true if we definitely know D is not null.
  bool isNotNull(const Decl *D);

  // Return true if we definitely know D is null.
  bool isNull(const Decl *D);

  void inverse();
  void merge(NullScope &ns);
};

#endif // NULLSCOPE_H
