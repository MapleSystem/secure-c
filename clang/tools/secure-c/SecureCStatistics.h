#ifndef SECURECSTATISTICS_H
#define SECURECSTATISTICS_H

#include "clang/AST/AST.h"

using namespace clang;

class SecureCVisitor;

class SecureCStatistics {
private:
  SecureCVisitor *SCV;

  unsigned int Dereferences = 0;
  unsigned int MemberAccesses = 0;
  unsigned int ArraySubscripts = 0;
  unsigned int FunctionCalls = 0;
  unsigned int Casts = 0;

  unsigned int SafeByAnnotation = 0;
  unsigned int SafeByAnalysis = 0;
  unsigned int ChecksInserted = 0;
  unsigned int DuplicateChecks = 0;
  unsigned int RedundantChecks = 0;

public:
  SecureCStatistics(SecureCVisitor *SCV);

  enum PtrContext { deref, member, subscript, call, cast };

  void trackStatistics(const Expr *E, PtrContext Context);
  void insertCheck();
  void duplicateCheck();
  void redundantCheck();
  void reportStatistics(bool DebugMode);

private:
  bool checkPointer(const Expr *E);
};

#endif // SECURECSTATISTICS_H
