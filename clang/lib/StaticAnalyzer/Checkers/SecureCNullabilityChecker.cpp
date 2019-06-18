//== SecureCNullabilityChecker.cpp ----------------------------------- -*- C++
//-*--=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker defines hooks to detect pointer nullability.
//
//===----------------------------------------------------------------------===//
#include "clang/AST/Attr.h"
#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

#include "llvm/Support/Debug.h"
#include <stdio.h>

#include <climits>
#include <initializer_list>
#include <iostream>
#include <utility>
using namespace clang;
using namespace ento;

using namespace llvm;

namespace {
class SecureCNullabilityChecker
    : public Checker<check::Location, check::PreCall, check::BranchCondition,
                     check::PreStmt<ReturnStmt>, check::PreStmt<CallExpr>> {
  // Errors
  mutable std::unique_ptr<BuiltinBug> UndefPtrDeref;
  mutable std::unique_ptr<BuiltinBug> NullOrUndefPtr;

  // Warnings
  std::unique_ptr<BugType> RedundantNullCheck;

  enum NullErrorKind {
    NullPtrDereference,
    UndefPtrDereference,
    NullPtrParameter,
    UndefPtrParameter,
    NullPtrAccess,
    NullErrorEnd
  };

  void TriageArgPointer(SVal L, const Expr *expr, CheckerContext &C) const;

  void reportBug(ProgramStateRef State, const Stmt *S, CheckerContext &C,
                 NullErrorKind ErrorKind) const;

  void reportWarning(CheckerContext &C, const Expr *Arg) const;

public:
  SecureCNullabilityChecker();

  void checkLocation(SVal location, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *S, CheckerContext &C) const;
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end of anonymous namespace

SecureCNullabilityChecker::SecureCNullabilityChecker() {
  // Warnings
  RedundantNullCheck.reset(
      new BugType(this, "Nonnull annotated pointer is checked for Null",
                  "Secure-C Nullability Checker"));
}

void SecureCNullabilityChecker::reportBug(ProgramStateRef State, const Stmt *S,
                                          CheckerContext &C,
                                          NullErrorKind ErrorKind) const {

  // Generate an error node.
  ExplodedNode *N = C.generateErrorNode(State);
  if (!N)
    return;

  if (!NullOrUndefPtr)
    NullOrUndefPtr.reset(new BuiltinBug(this, "Nullability checker"));

  SmallString<100> buf;
  llvm::raw_svector_ostream os(buf);
  auto expr = dyn_cast<Expr>(S);

  switch (ErrorKind) {
  case NullErrorKind::NullPtrDereference:
    os << "Dereferencing a nullptr";
    break;
  case NullErrorKind::UndefPtrDereference:
    os << "Dereferencing of undefined pointer";
    break;
  case NullErrorKind::NullPtrParameter:
    os << "Null pointer passed when the parameter is Nonnull "
          "annotated";
    break;
  case NullErrorKind::UndefPtrParameter:
    os << "Undefined pointer passed when the parameter is "
          "Nonnull annotated";
    break;
  case NullErrorKind::NullPtrAccess:
    os << "Illegal access of nullable pointer type";
    break;
  default:
    os << "Unknown error description";
    break;
  }

  auto report = llvm::make_unique<BugReport>(*NullOrUndefPtr, os.str(), N);
  bugreporter::trackExpressionValue(N, expr, *report);
  C.emitReport(std::move(report));
}

void SecureCNullabilityChecker::reportWarning(CheckerContext &C,
                                              const Expr *Arg) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *RedundantNullCheck,
        "Known Nonnull annotated pointer is checked for Null", N);
    report->addRange(Arg->getSourceRange());
    C.emitReport(std::move(report));
  }
}

static const Expr *getDereferenceExpr(const Stmt *S, bool IsBind = false) {
  const Expr *E = nullptr;

  // Walk through lvalue casts to get the original expression
  // that syntactically caused the load.
  if (const Expr *expr = dyn_cast<Expr>(S))
    E = expr->IgnoreParenLValueCasts();

  if (IsBind) {
    const VarDecl *VD;
    const Expr *Init;
    std::tie(VD, Init) = parseAssignment(S);
    if (VD && Init)
      E = Init;
  }
  return E;
}

void SecureCNullabilityChecker::TriageArgPointer(SVal L, const Expr *expr,
                                                 CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool undefPtr = L.isUndef(); // TODO: To be verified
  bool isPtrNull = State->isNull(L).isConstrainedTrue();
  if (expr->getType()->isPointerType()) {
    if (getNullabilityAnnotation(expr->getType()) == Nullability::Nonnull &&
        (undefPtr || isPtrNull)) {
      // Report Error
      auto ec = (isPtrNull) ? NullErrorKind::NullPtrParameter
                            : NullErrorKind::UndefPtrParameter;
      reportBug(State, expr, C, ec);
    }
  }
}

void SecureCNullabilityChecker::checkLocation(SVal l, bool isLoad,
                                              const Stmt *S,
                                              CheckerContext &C) const {
  dbgs() << "Check Location\n";

  ProgramStateRef state = C.getState();

  // Check if the pointer is undefined
  if (l.isUndef()) {
    if (ExplodedNode *N = C.generateErrorNode()) {
      if (!UndefPtrDeref)
        UndefPtrDeref.reset(
            new BuiltinBug(this, "Dereferencing an undefined pointer"));
      auto report = llvm::make_unique<BugReport>(
          *UndefPtrDeref, UndefPtrDeref->getDescription(), N);
      bugreporter::trackExpressionValue(N, bugreporter::getDerefExpr(S),
                                        *report);
      C.emitReport(std::move(report));
      return;
    }
  }

  // Check if the pointer is NULL
  DefinedOrUnknownSVal location = l.castAs<DefinedOrUnknownSVal>();

  if (!location.getAs<Loc>())
    return;

  ProgramStateRef notNullState, nullState;
  std::tie(notNullState, nullState) = state->assume(location);

  if (nullState && !notNullState) {
    const Expr *expr = getDereferenceExpr(S);
    if (!expr->getType().getQualifiers().hasAddressSpace()) {
      reportBug(nullState, expr, C, NullPtrDereference);
    }
  }
}

void SecureCNullabilityChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  dbgs() << "Check PreCall\n";
  if (!Call.getDecl())
    return;

  unsigned numArgs = Call.getNumArgs();
  auto Parameters = Call.parameters();
  for (unsigned idx = 0; idx < numArgs; idx++) {
    const Expr *expr = Call.getArgExpr(idx);
    SVal L = Call.getArgSVal(idx);
    TriageArgPointer(L, expr, C);
  }
}

void SecureCNullabilityChecker::checkPreStmt(const ReturnStmt *S,
                                             CheckerContext &C) const {
  dbgs() << "Check PreStmt: ReturnStmt\n";

  ProgramStateRef State = C.getState();

  const Expr *retExpr = S->getRetValue();

  if (retExpr->getType()->isPointerType()) {
    QualType RequiredRetType;
    AnalysisDeclContext *DeclCtxt =
        C.getLocationContext()->getAnalysisDeclContext();
    const Decl *D = DeclCtxt->getDecl();
    if (auto *FD = dyn_cast<FunctionDecl>(D))
      RequiredRetType = FD->getReturnType();
    else
      return;

    Nullability RequiredNullability = getNullabilityAnnotation(RequiredRetType);
    bool isRetNonnullAnnotated = (RequiredNullability == Nullability::Nonnull);
    bool isPtrNullableAnnotated =
        (getNullabilityAnnotation(retExpr->getType()) == Nullability::Nullable);
    if (isPtrNullableAnnotated && isRetNonnullAnnotated)
      reportBug(State, retExpr, C, NullErrorKind::NullPtrAccess);
    return;
  }

  if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(retExpr)) {
    if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(ICE->getSubExpr())) {
      if (UO->getOpcode() == UO_Deref) {
        bool isNullableAnnotated =
            (getNullabilityAnnotation(UO->getSubExpr()->getType()) ==
             Nullability::Nullable);
        if (isNullableAnnotated)
          reportBug(State, retExpr, C, NullPtrDereference);
      }
    }
  }
}

void SecureCNullabilityChecker::checkPreStmt(const CallExpr *CE,
                                             CheckerContext &C) const {
  dbgs() << "Check PreStmt: CallExpr\n";

  for (unsigned idx = 0; idx < CE->getNumArgs(); idx++) {
    const Expr *arg = CE->getArg(idx);
    SVal L = C.getSVal(arg);
    TriageArgPointer(L, arg, C);
  }
}

void SecureCNullabilityChecker::checkBranchCondition(const Stmt *Condition,
                                                     CheckerContext &C) const {
  dbgs() << "Check BranchCondition\n";

  ProgramStateRef State = C.getState();

  if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(Condition)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      // x == NULL OR x != NULL
      if (BO->getRHS()->isNullPointerConstant(C.getASTContext(),
                                              Expr::NPC_NeverValueDependent) !=
          Expr::NPCK_NotNull) {
        const Expr *LHS = BO->getLHS();
        if (LHS->getType()->isPointerType()) {
          if (getNullabilityAnnotation(LHS->getType()) ==
              Nullability::Nonnull) {
            reportWarning(C, LHS);
          }
        }
      }
      // NULL == x OR NULL != x
      if (BO->getLHS()->isNullPointerConstant(C.getASTContext(),
                                              Expr::NPC_NeverValueDependent) !=
          Expr::NPCK_NotNull) {
        const Expr *RHS = BO->getRHS();
        if (RHS->getType()->isPointerType()) {
          if (getNullabilityAnnotation(RHS->getType()) ==
              Nullability::Nonnull) {
            reportWarning(C, RHS);
          }
        }
      }
    }
  }
}

void ento::registerSecureCNullabilityChecker(CheckerManager &mgr) {
  mgr.registerChecker<SecureCNullabilityChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterSecureCNullabilityChecker(const LangOptions &LO) {
  return true;
}