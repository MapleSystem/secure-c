//== SecureBufferChecker.cpp - Secure buffer annotation checker ---*-C++-*--==//
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
class SecureBufferChecker : public Checker<check::PreCall, check::Location> {
  std::unique_ptr<BugType> PossiblyBreaksConstraints;
  std::unique_ptr<BugType> BreaksConstraints;
  std::unique_ptr<BugType> PossiblyOutOfBounds;
  std::unique_ptr<BugType> OutOfBounds;
  std::unique_ptr<BugType> UnknownLength;

  void reportConstraintWarning(CheckerContext &C, const Stmt *S) const;
  void reportConstraintError(CheckerContext &C, const Stmt *S) const;
  void reportAccessWarning(CheckerContext &C, const Stmt *S) const;
  void reportAccessError(CheckerContext &C, const Stmt *S) const;
  void reportUnknownLength(CheckerContext &C, const Stmt *S) const;

  SVal createSValForExpr(SValBuilder &SVB, CheckerContext &C,
                         std::map<const Decl *, SVal> &ParamToArg,
                         const Expr *E) const;
  DefinedOrUnknownSVal getBufferLength(CheckerContext &C, SValBuilder &SVB,
                                       SVal Val) const;

public:
  SecureBufferChecker();

  // Process arguments at call-sites
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal location, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;
};

} // end anonymous namespace

SecureBufferChecker::SecureBufferChecker() {
  // Initialize the bug types.
  PossiblyOutOfBounds.reset(
      new BugType(this, "Possibly out of range", "Secure-C Secure Buffer"));
  OutOfBounds.reset(
      new BugType(this, "Out of range", "Secure-C Secure Buffer"));
  PossiblyBreaksConstraints.reset(new BugType(
      this, "Possibly breaks constraints", "Secure-C Secure Buffer"));
  BreaksConstraints.reset(
      new BugType(this, "Breaks constraints", "Secure-C Secure Buffer"));
}

void SecureBufferChecker::reportConstraintWarning(CheckerContext &C,
                                                  const Stmt *S) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *PossiblyBreaksConstraints,
        "Argument may not satisfy secure_buffer constraints", N);
    report->addRange(S->getSourceRange());
    C.emitReport(std::move(report));
  }
}

void SecureBufferChecker::reportConstraintError(CheckerContext &C,
                                                const Stmt *S) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *BreaksConstraints,
        "Argument does not satisfy secure_buffer constraints", N);
    report->addRange(S->getSourceRange());
    C.emitReport(std::move(report));
  }
}

void SecureBufferChecker::reportAccessWarning(CheckerContext &C,
                                              const Stmt *S) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *PossiblyOutOfBounds, "Access may be out of bounds", N);
    report->addRange(S->getSourceRange());
    C.emitReport(std::move(report));
  }
}

void SecureBufferChecker::reportAccessError(CheckerContext &C,
                                            const Stmt *S) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(*OutOfBounds,
                                               "Access is out of bounds", N);
    report->addRange(S->getSourceRange());
    C.emitReport(std::move(report));
  }
}

void SecureBufferChecker::reportUnknownLength(CheckerContext &C,
                                              const Stmt *S) const {
  if (const ExplodedNode *N = C.generateNonFatalErrorNode()) {
    auto report = llvm::make_unique<BugReport>(
        *UnknownLength, "Unsafe access of pointer to unknown buffer size", N);
    report->addRange(S->getSourceRange());
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

DefinedOrUnknownSVal SecureBufferChecker::getBufferLength(CheckerContext &C,
                                                          SValBuilder &SVB,
                                                          SVal Val) const {
  const MemRegion *R = Val.getAsRegion();
  if (!R) {
    return UnknownVal();
  }

  if (R->getKind() != MemRegion::ElementRegionKind) {
    return UnknownVal();
  }
  const ElementRegion *ER = cast<ElementRegion>(R);
  QualType ElementType = ER->getElementType();
  // If the element is an incomplete type, go no further.
  if (ElementType->isIncompleteType())
    return UnknownVal();

  const SubRegion *SR = dyn_cast_or_null<SubRegion>(R->getBaseRegion());
  if (!SR) {
    return UnknownVal();
  }
  DefinedOrUnknownSVal Extent = SR->getExtent(SVB);

  ASTContext &AstContext = C.getASTContext();
  CharUnits TypeSize = AstContext.getTypeSizeInChars(ElementType);
  SVal NumElements = SVB.evalBinOp(C.getState(), BO_Div, Extent,
                                   SVB.makeArrayIndex(TypeSize.getQuantity()),
                                   SVB.getArrayIndexType());
  return NumElements.castAs<DefinedOrUnknownSVal>();
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
      DefinedOrUnknownSVal Length = getBufferLength(C, SVB, ArgVal);
      if (Length.isUnknown()) {
        reportConstraintWarning(C, Call.getArgExpr(i));
        continue;
      }

      const Expr *ReqLengthExpr = SBA->getLength();
      DefinedOrUnknownSVal ReqLength =
          createSValForExpr(SVB, C, ParamToArg, ReqLengthExpr)
              .castAs<DefinedOrUnknownSVal>();

      SVal InRange = SVB.evalBinOp(state, BO_GE, Length, ReqLength,
                                   SVB.getArrayIndexType());

      ProgramStateRef StInBound, StOutBound;
      std::tie(StInBound, StOutBound) =
          state->assume(InRange.castAs<DefinedOrUnknownSVal>());

      if (StOutBound && !StInBound) {
        reportConstraintError(C, Call.getArgExpr(i));
      } else if ((bool)StInBound == (bool)StOutBound) {
        reportConstraintWarning(C, Call.getArgExpr(i));
      }
    }
  }
}

void SecureBufferChecker::checkLocation(SVal location, bool isLoad,
                                        const Stmt *S,
                                        CheckerContext &C) const {
  SValBuilder &SVB = C.getSValBuilder();
  ProgramStateRef state = C.getState();

  const MemRegion *Region = location.getAsRegion();
  const ElementRegion *ER = dyn_cast_or_null<ElementRegion>(Region);
  if (!ER) {
    return;
  }

  DefinedOrUnknownSVal Length = getBufferLength(C, SVB, location);
  if (Length.isUnknown()) {
    reportUnknownLength(C, S);
    return;
  }

  ProgramStateRef StInBound =
      state->assumeInBound(ER->getIndex(), Length, true);
  ProgramStateRef StOutBound =
      state->assumeInBound(ER->getIndex(), Length, false);

  if (StOutBound && !StInBound) {
    reportAccessError(C, S);
  } else if ((bool)StInBound == (bool)StOutBound) {
    reportAccessWarning(C, S);
  }
}

void ento::registerSecureBufferChecker(CheckerManager &mgr) {
  mgr.registerChecker<SecureBufferChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterSecureBufferChecker(const LangOptions &LO) {
  return true;
}
