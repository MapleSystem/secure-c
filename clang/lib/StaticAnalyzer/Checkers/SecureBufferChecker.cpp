//== SecureBufferChecker.cpp - Value range annotation checker -----*-C++-*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This defines SecureBufferChecker, a checker that checks for appropriate
// usage of buffers passed around as pointers by tracking the size of the
// pointed-to buffer using the `secure_buffer` annotation.
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
class SecureBufferChecker : public Checker<check::PreCall> {
  std::unique_ptr<BugType> PossiblyOutOfRange;
  std::unique_ptr<BugType> OutOfRange;

  void reportWarning(CheckerContext &C, const Expr *Arg) const;
  void reportError(CheckerContext &C, const Expr *Arg) const;

  SVal createSValForExpr(SValBuilder &SVB, CheckerContext &C,
                         std::map<const Decl *, SVal> &ParamToArg,
                         const Expr *E) const;

public:
  SecureBufferChecker();

  // Process arguments at call-sites
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

SecureBufferChecker::SecureBufferChecker() {
  // Initialize the bug types.
  PossiblyOutOfRange.reset(
      new BugType(this, "Possibly out of range", "Secure-C Secure Buffer"));
  OutOfRange.reset(new BugType(this, "Out of range", "Secure-C Secure Buffer"));
}

void SecureBufferChecker::reportWarning(CheckerContext &C,
                                        const Expr *Arg) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *PossiblyOutOfRange,
        "Argument may not satisfy secure_buffer constraints", N);
    report->addRange(Arg->getSourceRange());
    C.emitReport(std::move(report));
  }
}

void SecureBufferChecker::reportError(CheckerContext &C,
                                      const Expr *Arg) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *OutOfRange, "Argument does not satisfy secure_buffer constraints", N);
    report->addRange(Arg->getSourceRange());
    C.emitReport(std::move(report));
  }
}

SVal SecureBufferChecker::createSValForExpr(
    SValBuilder &SVB, CheckerContext &C,
    std::map<const Decl *, SVal> &ParamToArg, const Expr *E) const {
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    return SVB.makeIntVal(IL);
  } else if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    std::map<const Decl *, SVal>::iterator found =
        ParamToArg.find(DRE->getDecl());
    if (found == ParamToArg.end()) {
      return UndefinedVal();
    } else {
      return found->second;
    }
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

// On function calls, check if the pointer passed to a parameter with a
// secure-buffer annotation has a valid length.
void SecureBufferChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  const AnyFunctionCall *FC = dyn_cast<AnyFunctionCall>(&Call);
  if (!FC)
    return;

  const FunctionDecl *FD = FC->getDecl();
  if (!FD)
    return;

  SValBuilder &SVB = C.getSValBuilder();
  ProgramStateRef state = C.getState();

  std::map<const Decl *, SVal> ParamToArg;
  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    ParamToArg[FD->getParamDecl(i)] = Call.getArgSVal(i);
  }

  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (SecureBufferAttr *SBA = PVD->getAttr<SecureBufferAttr>()) {
      SVal ArgVal = Call.getArgSVal(i);
      const MemRegion *R = ArgVal.getAsRegion();
      if (!R) {
        reportWarning(C, Call.getArgExpr(i));
        continue;
      }

      const SubRegion *SR = dyn_cast_or_null<SubRegion>(R->getBaseRegion());
      if (!SR) {
        reportWarning(C, Call.getArgExpr(i));
        continue;
      }
      DefinedOrUnknownSVal Extent = SR->getExtent(SVB);

      const PointerType *PT =
          dyn_cast<PointerType>(PVD->getType().getCanonicalType().getTypePtr());
      assert(PT);
      QualType ElementType = PT->getPointeeType();
      ASTContext &AstContext = C.getASTContext();
      CharUnits TypeSize = AstContext.getTypeSizeInChars(ElementType);
      SVal NumElements = SVB.evalBinOp(
          state, BO_Div, Extent, SVB.makeArrayIndex(TypeSize.getQuantity()),
          SVB.getArrayIndexType());

      const Expr *ReqLengthExpr = SBA->getLength();
      DefinedOrUnknownSVal ReqLength =
          createSValForExpr(SVB, C, ParamToArg, ReqLengthExpr)
              .castAs<DefinedOrUnknownSVal>();

      SVal InRange = SVB.evalBinOp(state, BO_GE, NumElements, ReqLength,
                                   SVB.getArrayIndexType());

      std::pair<ProgramStateRef, ProgramStateRef> states =
          state->assume(InRange.castAs<DefinedOrUnknownSVal>());

      ProgramStateRef StInBound = states.first;
      ProgramStateRef StOutBound = states.second;
      if (StOutBound && !StInBound) {
        reportError(C, Call.getArgExpr(i));
      } else if (StInBound == StOutBound) {
        reportWarning(C, Call.getArgExpr(i));
      }
    }
  }
}

void ento::registerSecureBufferChecker(CheckerManager &mgr) {
  mgr.registerChecker<SecureBufferChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterSecureBufferChecker(const LangOptions &LO) {
  return true;
}
