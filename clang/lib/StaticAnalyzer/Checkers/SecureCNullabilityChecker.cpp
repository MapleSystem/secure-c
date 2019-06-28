//== SecureCNullabilityChecker.cpp ---------------------------------*-C++-*--=//
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
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/SecureCCommon.h"
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

#define DEBUG_TYPE "Secure-C Nullability"

namespace {
class SecureCNullabilityChecker
    : public Checker<check::BeginFunction, check::PreCall,
                     check::BranchCondition, check::PreStmt<ReturnStmt>,
                     check::PreStmt<CallExpr>, check::PreStmt<UnaryOperator>,
                     check::PreStmt<MemberExpr>,
                     check::PreStmt<ArraySubscriptExpr>> {
  // Errors
  mutable std::unique_ptr<BugType> BT;

  enum NullErrorKind {
    NullablePtrAccess,
    UnsafePromotion,
    UnmetInConstraint,
    UnmetOutConstraint,
    RedundantNullCheck,
    NullErrorEnd
  };

  void TriageArgPointer(SVal L, const Expr *expr, CheckerContext &C) const;

  void reportBug(CheckerContext &C, NullErrorKind ErrorKind,
                 SourceRange Range) const;

public:
  void checkBeginFunction(CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const ReturnStmt *S, CheckerContext &C) const;
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;
  void checkPreStmt(const MemberExpr *ME, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const;
};

} // end of anonymous namespace

LLVM_DUMP_METHOD static void debug_error(CheckerContext &C, const Stmt *S, SVal Val) {
  llvm::errs() << "Stmt with error:\n";
  S->dump();
  llvm::errs() << "Val: ";
  Val.dump();
  llvm::errs() << "\n";
  C.getState()->getConstraintManager().print(C.getState(), llvm::errs(), "\n", "");
}

void SecureCNullabilityChecker::reportBug(CheckerContext &C,
                                          NullErrorKind ErrorKind,
                                          SourceRange Range) const {

  const ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  if (!BT)
    BT.reset(new BugType(this, "Nullability", "Secure-C"));

  SmallString<100> buf;
  llvm::raw_svector_ostream os(buf);

  switch (ErrorKind) {
  case NullErrorKind::UnsafePromotion:
    os << "unsafe promotion from nullable pointer to non-null pointer";
    break;
  case NullErrorKind::UnmetInConstraint:
    os << "callee's in-constraint is not satisfied";
    break;
  case NullErrorKind::UnmetOutConstraint:
    os << "out-constraint is not satisfied upon return";
    break;
  case NullErrorKind::NullablePtrAccess:
    os << "illegal access of nullable pointer";
    break;
  case NullErrorKind::RedundantNullCheck:
    os << "redundant null check";
    break;
  default:
    os << "Unknown error description";
    break;
  }

  auto report = llvm::make_unique<BugReport>(*BT, os.str(), N);
  report->addRange(Range);
  C.emitReport(std::move(report));
}

void SecureCNullabilityChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  const auto *LCtx = C.getLocationContext();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  // Add assumptions for incoming nullability annotations
  for (auto *SCInA : FD->specific_attrs<SecureCInAttr>()) {
    Expr *Target = SCInA->getTarget();
    DefinedOrUnknownSVal Val = getValueForExpr(C, State, SVB, Target, LCtx);

    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      Expr *AExpr = *APtr;
      DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(AExpr);
      if (!DRE)
        continue;

      NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl());
      if (!ND)
        continue;

      if (ND->getName().equals("nonnull")) {
        SVal NotNullVal = SVB.evalBinOp(State, BO_NE, Val,
                                        SVB.makeNullWithType(Target->getType()),
                                        SVB.getConditionType());
        assert(!NotNullVal.isUndef());
        State = State->assume(NotNullVal.castAs<DefinedOrUnknownSVal>(), true);
      }
    }
  }

  C.addTransition(State);
}

void SecureCNullabilityChecker::checkPreCall(const CallEvent &Call,
                                             CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  ProgramStateRef State = C.getState();
  SValBuilder &SVB = C.getSValBuilder();

  // Check `secure_c_in` requirements of callee
  for (auto *SCInA : FD->specific_attrs<SecureCInAttr>()) {
    Expr *Target = SCInA->getTarget();
    SVal TargetVal = createSValForParamExpr(SVB, C, Call, Target);
    assert(!TargetVal.isUndef());

    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      Expr *AExpr = *APtr;
      DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(AExpr);
      if (!DRE)
        continue;

      NamedDecl *ND = dyn_cast<NamedDecl>(DRE->getDecl());
      if (!ND)
        continue;

      if (ND->getName().equals("nonnull")) {
        if (State->assume(TargetVal.castAs<DefinedOrUnknownSVal>(), false)) {
          // debug_error(C, Target, TargetVal);
          reportBug(C, UnmetInConstraint, Call.getSourceRange());
        }
      }
    }
  }
}

void SecureCNullabilityChecker::checkPreStmt(const ReturnStmt *S,
                                             CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *retExpr = S->getRetValue();
  if (!retExpr)
    return;

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
      reportBug(C, UnsafePromotion, retExpr->getSourceRange());
    return;
  }
}

void SecureCNullabilityChecker::checkPreStmt(const CallExpr *CE,
                                             CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *Callee = CE->getCallee();
  if (Callee->IgnoreParenImpCasts()->isLValue()) {
    SVal Val = getValueForExpr(C, State, C.getSValBuilder(), Callee,
                               C.getLocationContext());
    if (Val.isUndef() ||
        State->assume(Val.castAs<DefinedOrUnknownSVal>(), false)) {
      // debug_error(C, CE, Val);
      reportBug(C, NullablePtrAccess, CE->getSourceRange());
      return;
    }
  }
}

void SecureCNullabilityChecker::checkPreStmt(const UnaryOperator *UO,
                                             CheckerContext &C) const {
  if (UO->getOpcode() != UO_Deref)
    return;

  ProgramStateRef State = C.getState();

  const Expr *Pointer = UO->getSubExpr();
  SVal Val = getValueForExpr(C, State, C.getSValBuilder(), Pointer,
                             C.getLocationContext());
  if (Val.isUndef() ||
      State->assume(Val.castAs<DefinedOrUnknownSVal>(), false)) {
    // debug_error(C, UO, Val);
    reportBug(C, NullablePtrAccess, UO->getSourceRange());
    return;
  }
}

void SecureCNullabilityChecker::checkPreStmt(const MemberExpr *ME,
                                             CheckerContext &C) const {
  if (!ME->isArrow())
    return;

  ProgramStateRef State = C.getState();

  const Expr *Pointer = ME->getBase();
  SVal Val = getValueForExpr(C, State, C.getSValBuilder(), Pointer,
                             C.getLocationContext());
  if (Val.isUndef() ||
      State->assume(Val.castAs<DefinedOrUnknownSVal>(), false)) {
    // debug_error(C, ME, Val);
    reportBug(C, NullablePtrAccess, ME->getSourceRange());
    return;
  }
}

void SecureCNullabilityChecker::checkPreStmt(const ArraySubscriptExpr *ASE,
                                             CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  const Expr *Pointer = ASE->getBase();
  SVal Val = getValueForExpr(C, State, C.getSValBuilder(), Pointer,
                             C.getLocationContext());
  if (Val.isUndef() ||
      State->assume(Val.castAs<DefinedOrUnknownSVal>(), false)) {
    // debug_error(C, ASE, Val);
    reportBug(C, NullablePtrAccess, ASE->getSourceRange());
    return;
  }
}

void SecureCNullabilityChecker::checkBranchCondition(const Stmt *Condition,
                                                     CheckerContext &C) const {
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
            reportBug(C, RedundantNullCheck, LHS->getSourceRange());
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
            reportBug(C, RedundantNullCheck, RHS->getSourceRange());
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
