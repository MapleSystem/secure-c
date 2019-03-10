#ifndef SECUREC_H
#define SECUREC_H

#include <string>

#include "clang/AST/AST.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/Tooling.h"

#include "NullScope.h"

using namespace clang;
using namespace clang::tooling;

class SecureCStatistics;

class SecureCVisitor : public RecursiveASTVisitor<SecureCVisitor> {
public:
  explicit SecureCVisitor(
      ASTContext &Context,
      std::map<std::string, tooling::Replacements> &FileToReplaces);

  bool shouldTraversePostOrder();
  bool TraverseDecl(Decl *D);
  bool VisitVarDecl(VarDecl *VD);
  bool TraverseFunctionDecl(FunctionDecl *FD);
  bool TraverseIfStmt(IfStmt *If);
  bool VisitBinaryOperator(BinaryOperator *BO);
  bool VisitAssign(Expr *LHS, Expr *RHS);
  bool VisitFuncPtrAssign(const QualType &Ty, const Expr *RHS);
  bool VisitCallExpr(CallExpr *CE);
  bool VisitMemberExpr(MemberExpr *ME);
  bool VisitArraySubscriptExpr(ArraySubscriptExpr *AE);
  bool VisitUnaryOperator(UnaryOperator *UO);
  bool VisitReturnStmt(ReturnStmt *RS);

  bool isDeterminedNonNull(const Expr *E);
  void reportStatistics(bool DebugMode);

private:
  ASTContext &Context;
  std::vector<std::unique_ptr<NullScope>> NullScopes;
  std::map<std::string, tooling::Replacements> &FileToReplaces;
  std::map<uint64_t, bool> InsertedChecks;
  SecureCStatistics *Stats;

  void insertRuntimeNullCheck(const Expr *Pointer);
  void insertRuntimeRangeCheck(const Expr *Val, const Expr *Cond);
  StringRef getSourceString(const Expr *Pointer, CharSourceRange &Range);
  bool isDuplicateReplacement(Replacement &Old, Replacement &New);
  bool isExistingReplacementInside(Replacement &Old, Replacement &New);
  llvm::Error handleReplacementError(llvm::Error Err, std::string PtrExpr,
                                     std::string TyString);

  void reportIllegalCast(const QualType &Ty, const Expr *Pointer,
                         const ASTContext &Context);
  void reportIllegalAccess(const Expr *Pointer, const Expr *Access,
                           const ASTContext &Context);
  void reportUnannotatedParam(const FunctionDecl *FD, const ParmVarDecl *Param,
                              bool suggestNonnull, const ASTContext &Context);
  void reportUninitializedNonnull(const VarDecl *VD, const ASTContext &Context);
  void reportIllegalCastFuncPtr(const Expr *rhs, const ASTContext &Context);
  void warnRedundantCheck(const Expr *Check);
  void reportFailedReplacement(const Expr *Pointer, std::string ErrMsg);
  void reportFailedHeaderInsert(std::string ErrMsg);
  void reportMissingSecureBuffer(const Expr *Pointer, const Expr *Access);
  void reportUncheckedSecureBuffer(const Expr *Access, const Expr *Index,
                                   const Expr *Length, const Expr *Cond);
  void reportSecureBufferOutOfRange(const Expr *Access, const Expr *Index);

  bool isNullabilityAnnotated(const QualType &QT);
  bool hasValueRange(const FunctionDecl *FD);
  bool isNonnullCompatible(Expr const *E);
};

bool isAnnotatedNonnull(const QualType &QT);

#endif // SECUREC_H
