//== ValueRangeChecker.cpp - Value range annotation checker -------*-C++-*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This defines ValueRangeChecker, a checker that checks value ranges of
// arguments passed to parameters with `value_range` attributes.
//
//===----------------------------------------------------------------------===//

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/SecureCCommon.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class ValueRangeChecker
    : public Checker<check::PreCall, check::PostCall, check::BeginFunction> {
  std::unique_ptr<BugType> PossiblyOutOfRange;
  std::unique_ptr<BugType> OutOfRange;

  const Expr *getValueRangeCondition(const FunctionDecl *FD,
                                     ValueRangeAttr *VRA) const;

  void reportWarning(CheckerContext &C, const Expr *Arg) const;
  void reportError(CheckerContext &C, const Expr *Arg) const;

  enum ValueRangeResult { VRUndefined, VRInRange, VROutOfRange };

  ValueRangeResult isInValueRange(SValBuilder &SVB, CheckerContext &C,
                                  const CallEvent &Call, const Expr *TargetExpr,
                                  SVal Target, const Expr *MinExpr,
                                  const Expr *MaxExpr) const;

public:
  ValueRangeChecker();

  // Process arguments at call-sites
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;

private:
  void checkValueRangeAttr(const CallEvent &Call, CheckerContext &C,
                           const ParmVarDecl *PVD, const Expr *MinExpr,
                           const Expr *MaxExpr, unsigned Idx) const;
};

} // end anonymous namespace

ValueRangeChecker::ValueRangeChecker() {
  // Initialize the bug types.
  PossiblyOutOfRange.reset(
      new BugType(this, "Possibly out of range", "Secure-C Value Range"));
  OutOfRange.reset(new BugType(this, "Out of range", "Secure-C Value Range"));
}

void ValueRangeChecker::reportWarning(CheckerContext &C,
                                      const Expr *Arg) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *PossiblyOutOfRange, "Argument may not satisfy value_range constraints",
        N);
    report->addRange(Arg->getSourceRange());
    C.emitReport(std::move(report));
  }
}

void ValueRangeChecker::reportError(CheckerContext &C, const Expr *Arg) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *OutOfRange, "Argument does not satisfy value_range constraints", N);
    report->addRange(Arg->getSourceRange());
    C.emitReport(std::move(report));
  }
}

ValueRangeChecker::ValueRangeResult
ValueRangeChecker::isInValueRange(SValBuilder &SVB, CheckerContext &C,
                                  const CallEvent &Call, const Expr *TargetExpr,
                                  SVal Target, const Expr *MinExpr,
                                  const Expr *MaxExpr) const {
  QualType Ty = TargetExpr->getType();

  SVal Min = createSValForParamExpr(SVB, C, Call, MinExpr);
  assert(!Min.isUnknownOrUndef());
  SVal Max = createSValForParamExpr(SVB, C, Call, MaxExpr);
  assert(!Max.isUnknownOrUndef());

  if (MinExpr->getType() != Ty)
    Min = SVB.evalCast(Min, Ty, MinExpr->getType());

  SVal MinCond = SVB.evalBinOp(C.getState(), BO_GE, Target, Min, Ty);

  const llvm::APSInt *MinResult = SVB.getKnownValue(C.getState(), MinCond);

  // If the min result is undefined, then the whole result is undefined
  if (MinResult == NULL)
    return VRUndefined;

  // If the min result is false, then the value is out of range
  if (!MinResult->getBoolValue())
    return VROutOfRange;

  if (MaxExpr->getType() != Ty)
    Max = SVB.evalCast(Max, Ty, MaxExpr->getType());

  SVal MaxCond = SVB.evalBinOp(C.getState(), BO_LE, Target, Max, Ty);

  const llvm::APSInt *MaxResult = SVB.getKnownValue(C.getState(), MaxCond);

  // If the max result is undefined, then the whole result is undefined
  if (!MaxResult)
    return VRUndefined;

  // If the max result is false, then the value is out of range
  if (!MaxResult->getBoolValue())
    return VROutOfRange;

  return VRInRange;
}

void ValueRangeChecker::checkPreCall(const CallEvent &Call,
                                     CheckerContext &C) const {
  const AnyFunctionCall *FC = dyn_cast<AnyFunctionCall>(&Call);
  if (!FC)
    return;

  const FunctionDecl *FD = FC->getDecl();
  if (!FD)
    return;

  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (ValueRangeAttr *VRA = PVD->getAttr<ValueRangeAttr>()) {
      checkValueRangeAttr(Call, C, PVD, VRA->getMin(), VRA->getMax(), i);
    }
  }

  // Process secure_c_in annotations, if any
  for (auto *SCInA : FD->specific_attrs<SecureCInAttr>()) {
    Expr *Target = SCInA->getTarget();
    auto *DRE = cast<DeclRefExpr>(Target);
    auto *PVD = cast<ParmVarDecl>(DRE->getDecl());
    unsigned TI = PVD->getFunctionScopeIndex();
    // Process annotations
    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      Expr *AExpr = *APtr;
      if (const auto *CE = dyn_cast<CallExpr>(AExpr)) {
        if (const FunctionDecl *FD = CE->getDirectCallee()) {
          const IdentifierInfo *II = FD->getIdentifier();
          if (II && II->getName().equals("value_range")) {
            checkValueRangeAttr(Call, C, PVD, CE->getArg(0), CE->getArg(1), TI);
          }
        }
      }
    }
  }
}

void ValueRangeChecker::checkPostCall(const CallEvent &Call,
                                      CheckerContext &C) const {
  const AnyFunctionCall *FC = dyn_cast<AnyFunctionCall>(&Call);
  if (!FC)
    return;

  const FunctionDecl *FD = FC->getDecl();
  if (!FD)
    return;

  // Process secure_c_out annotations, if any
  for (auto *SCInA : FD->specific_attrs<SecureCOutAttr>()) {
    Expr *Target = SCInA->getTarget();
    auto *DRE = cast<DeclRefExpr>(Target);
    auto *PVD = cast<ParmVarDecl>(DRE->getDecl());
    unsigned TI = PVD->getFunctionScopeIndex();
    // Process annotations
    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      Expr *AExpr = *APtr;
      if (const auto *CE = dyn_cast<CallExpr>(AExpr)) {
        if (const FunctionDecl *FD = CE->getDirectCallee()) {
          const IdentifierInfo *II = FD->getIdentifier();
          if (II && II->getName().equals("value_range")) {
            checkValueRangeAttr(Call, C, PVD, CE->getArg(0), CE->getArg(1), TI);
          }
        }
      }
    }
  }
}

void ValueRangeChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  ASTContext &Context = C.getASTContext();
  const auto *LCtx = C.getLocationContext();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  // Attributes on function parameters
  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (ValueRangeAttr *VRA = PVD->getAttr<ValueRangeAttr>()) {
      // Find parameter variable's symbolic value
      Loc ParamLoc = state->getLValue(PVD, LCtx);
      DefinedOrUnknownSVal ParamValue = state->getSVal(ParamLoc, PVD->getType())
                                            .castAs<DefinedOrUnknownSVal>();

      Expr *MinExpr = VRA->getMin();
      Expr *MaxExpr = VRA->getMax();

      Expr::EvalResult MinExprResult;
      if (!MinExpr->EvaluateAsInt(MinExprResult, Context)) {
        llvm_unreachable("Minimum value is not an integer constant");
      }
      llvm::APSInt LoBound = MinExprResult.Val.getInt();

      Expr::EvalResult MaxExprResult;
      if (!MaxExpr->EvaluateAsInt(MaxExprResult, Context)) {
        llvm_unreachable("Maximum value is not an integer constant");
      }
      llvm::APSInt HiBound = MaxExprResult.Val.getInt();

      state = state->assumeInclusiveRange(ParamValue, LoBound, HiBound, true);
    }
  }

  C.addTransition(state);
}

void ento::registerValueRangeChecker(CheckerManager &mgr) {
  mgr.registerChecker<ValueRangeChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterValueRangeChecker(const LangOptions &LO) {
  return true;
}

void ValueRangeChecker::checkValueRangeAttr(
    const CallEvent &Call, CheckerContext &C, const ParmVarDecl *PVD,
    const Expr *MinExpr, const Expr *MaxExpr, unsigned Idx) const {
  SValBuilder &SVB = C.getSValBuilder();
  ValueRangeResult Result =
      isInValueRange(SVB, C, Call, Call.getArgExpr(Idx), Call.getArgSVal(Idx),
                     MinExpr, MaxExpr);

  if (Result == VROutOfRange) {
    reportError(C, Call.getArgExpr(Idx));
  } else if (Result == VRUndefined) {
    reportWarning(C, Call.getArgExpr(Idx));
  }
}
