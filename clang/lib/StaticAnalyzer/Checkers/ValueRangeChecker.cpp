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
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class ValueRangeChecker : public Checker<check::PreCall> {
  std::unique_ptr<BugType> PossiblyOutOfRange;
  std::unique_ptr<BugType> OutOfRange;

  const Expr *getValueRangeCondition(const FunctionDecl *FD,
                                     ValueRangeAttr *VRA) const;

  void reportWarning(CheckerContext &C, const Expr *Arg) const;
  void reportError(CheckerContext &C, const Expr *Arg) const;

  SVal createSValForExpr(SValBuilder &SVB, CheckerContext &C,
                         std::map<const Decl *, SVal> &ParamToArg,
                         const Expr *E) const;

  enum ValueRangeResult { VRUndefined, VRInRange, VROutOfRange };

  ValueRangeResult isInValueRange(SValBuilder &SVB, CheckerContext &C,
                                  std::map<const Decl *, SVal> &ParamToArg,
                                  const Expr *TargetExpr, SVal Target,
                                  const Expr *MinExpr,
                                  const Expr *MaxExpr) const;

public:
  ValueRangeChecker();

  // Process arguments at call-sites
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
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

SVal ValueRangeChecker::createSValForExpr(
    SValBuilder &SVB, CheckerContext &C,
    std::map<const Decl *, SVal> &ParamToArg, const Expr *E) const {
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    return SVB.makeIntVal(IL);
  } else if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    return ParamToArg[DRE->getDecl()];
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    return SVB.evalBinOp(C.getState(), BO->getOpcode(),
                         createSValForExpr(SVB, C, ParamToArg, BO->getLHS()),
                         createSValForExpr(SVB, C, ParamToArg, BO->getRHS()),
                         BO->getType());
  } else if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    return SVB.evalCast(createSValForExpr(SVB, C, ParamToArg, CE->getSubExpr()),
                        CE->getType(), CE->getSubExpr()->getType());
  }

  return UndefinedVal();
}

ValueRangeChecker::ValueRangeResult ValueRangeChecker::isInValueRange(
    SValBuilder &SVB, CheckerContext &C,
    std::map<const Decl *, SVal> &ParamToArg, const Expr *TargetExpr,
    SVal Target, const Expr *MinExpr, const Expr *MaxExpr) const {
  QualType Ty = TargetExpr->getType();

  SVal Min = createSValForExpr(SVB, C, ParamToArg, MinExpr);
  assert(!Min.isUnknownOrUndef());
  SVal Max = createSValForExpr(SVB, C, ParamToArg, MaxExpr);
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

  SValBuilder &SVB = C.getSValBuilder();

  std::map<const Decl *, SVal> ParamToArg;
  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    ParamToArg[FD->getParamDecl(i)] = Call.getArgSVal(i);
  }

  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (ValueRangeAttr *VRA = PVD->getAttr<ValueRangeAttr>()) {
      const Expr *MinExpr = VRA->getMin();
      const Expr *MaxExpr = VRA->getMax();

      ValueRangeResult Result =
          isInValueRange(SVB, C, ParamToArg, Call.getArgExpr(i),
                         Call.getArgSVal(i), MinExpr, MaxExpr);

      if (Result == VROutOfRange) {
        reportError(C, Call.getArgExpr(i));
      } else if (Result == VRUndefined) {
        reportWarning(C, Call.getArgExpr(i));
      }
    }
  }
}

void ento::registerValueRangeChecker(CheckerManager &mgr) {
  mgr.registerChecker<ValueRangeChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterValueRangeChecker(const LangOptions &LO) {
  return true;
}
