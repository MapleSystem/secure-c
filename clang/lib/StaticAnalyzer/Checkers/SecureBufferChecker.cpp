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
  mutable std::unique_ptr<BugType> BT;

  enum SB_Kind {
    AccessIsOutOfBounds,
    AccessMayOutOfBounds,
    BreaksConstraint,
    MayBreakConstraint,
    UnknownLength
  };

  void reportBug(CheckerContext &C, SB_Kind Kind, const Stmt *S) const;

  SVal createSValForExpr(SValBuilder &SVB, CheckerContext &C,
                         std::map<const Decl *, SVal> &ParamToArg,
                         const Expr *E) const;
  DefinedOrUnknownSVal getBufferLength(CheckerContext &C, SValBuilder &SVB,
                                       SVal Val) const;

public:
  // Process arguments at call-sites
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal location, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;
};

} // end anonymous namespace

// Report an error detected by the secure-buffer checker.
void SecureBufferChecker::reportBug(CheckerContext &C, SB_Kind Kind,
                                    const Stmt *S) const {
  const ExplodedNode *N = C.generateNonFatalErrorNode();
  if (!N)
    return;

  if (!BT)
    BT.reset(new BugType(this, "Secure Buffer", "Secure-C"));

  SmallString<256> buf;
  llvm::raw_svector_ostream os(buf);
  os << "Buffer ";
  switch (Kind) {
  case AccessIsOutOfBounds:
    os << "access is out of bounds";
    break;
  case AccessMayOutOfBounds:
    os << "access may be out of bounds";
    break;
  case BreaksConstraint:
    os << "argument does not satisfy secure_buffer constraint";
    break;
  case MayBreakConstraint:
    os << "argument may not satisfy secure_buffer constraint";
    break;
  case UnknownLength:
    os << "has unknown length";
    break;
  }

  auto report = llvm::make_unique<BugReport>(*BT, os.str(), N);
  report->addRange(S->getSourceRange());
  C.emitReport(std::move(report));
}

// Given an expression in terms of the function parameters, create an SVal
// for it, replacing references to the parameters with the corresponding
// argument expressions.
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

// Attempt to get the length of the buffer, Val, in number of elements.
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
        reportBug(C, MayBreakConstraint, Call.getArgExpr(i));
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
        reportBug(C, BreaksConstraint, Call.getArgExpr(i));
      } else if ((bool)StInBound == (bool)StOutBound) {
        reportBug(C, MayBreakConstraint, Call.getArgExpr(i));
      }
    }
  }
}

// Upon accessing a memory location, check if it is within the secure-buffer
// boundaries.
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
    reportBug(C, UnknownLength, S);
    return;
  }

  ProgramStateRef StInBound =
      state->assumeInBound(ER->getIndex(), Length, true);
  ProgramStateRef StOutBound =
      state->assumeInBound(ER->getIndex(), Length, false);

  if (StOutBound && !StInBound) {
    reportBug(C, AccessIsOutOfBounds, S);
  } else if ((bool)StInBound == (bool)StOutBound) {
    reportBug(C, AccessMayOutOfBounds, S);
  }
}

void ento::registerSecureBufferChecker(CheckerManager &mgr) {
  mgr.registerChecker<SecureBufferChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterSecureBufferChecker(const LangOptions &LO) {
  return true;
}
