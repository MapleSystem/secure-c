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
#include "clang/StaticAnalyzer/Checkers/SecureCCommon.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class SecureBufferChecker
    : public Checker<check::PreCall, check::PostCall, check::Location,
                     check::BeginFunction, check::LiveSymbols,
                     check::DeadSymbols> {
  mutable std::unique_ptr<BugType> BT;

  enum SB_Kind {
    AccessIsOutOfBounds,
    AccessMayOutOfBounds,
    BreaksConstraint,
    MayBreakConstraint,
    UnknownLength
  };

  void reportBug(CheckerContext &C, SB_Kind Kind, const Stmt *S) const;

  DefinedOrUnknownSVal getBufferLength(CheckerContext &C, SValBuilder &SVB,
                                       SVal Val) const;

public:
  static void *getTag() {
    static int tag;
    return &tag;
  }

  // Process arguments at call-sites
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal location, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;

  void checkLiveSymbols(ProgramStateRef state, SymbolReaper &SR) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;

  void dump(ProgramStateRef state) const;

private:
  bool isSecureBufferAttr(const Expr *AttrExpr, const Expr *&LengthExpr) const;
  ProgramStateRef assumeSecureBufferAttr(CheckerContext &C,
                                         ProgramStateRef state, SVal TargetVal,
                                         QualType TargetType,
                                         const Expr *LengthExpr) const;
  void checkSecureBufferAttr(const CallEvent &Call, CheckerContext &C,
                             SVal TargetVal, QualType TargetType,
                             const Expr *LExpr) const;
};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(SecureBufferLength, const MemRegion *, SVal)

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

// Attempt to get the length of the buffer, Val, in number of bytes.
DefinedOrUnknownSVal SecureBufferChecker::getBufferLength(CheckerContext &C,
                                                          SValBuilder &SVB,
                                                          SVal Val) const {
  ProgramStateRef State = C.getState();

  const LocationInfo &LocInfo = LocationInfo::computeOffset(State, SVB, Val);

  const SubRegion *SR = LocInfo.getRegion();
  if (!SR)
    return UnknownVal();

  SVal Extent = SR->getExtent(SVB);

  NonLoc byteOffset = LocInfo.getByteOffset();

  Extent =
      SVB.evalBinOp(State, BO_Sub, Extent, byteOffset, SVB.getArrayIndexType());

  return Extent.castAs<DefinedOrUnknownSVal>();
}

static SVal elementCountToByteCount(CheckerContext &C, SVal Elements,
                                    QualType ElemType) {
  SValBuilder &SVB = C.getSValBuilder();
  CharUnits TypeSize = C.getASTContext().getTypeSizeInChars(ElemType);
  return SVB.evalBinOp(C.getState(), BO_Mul, Elements,
                       SVB.makeArrayIndex(TypeSize.getQuantity()),
                       SVB.getArrayIndexType());
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

  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (SecureBufferAttr *SBA = PVD->getAttr<SecureBufferAttr>()) {
      checkSecureBufferAttr(Call, C, Call.getArgSVal(i), PVD->getType(),
                            SBA->getLength());
    }
  }

  // Process secure_c_in annotations, if any
  for (auto *SCInA : FD->specific_attrs<SecureCInAttr>()) {
    Expr *Target = SCInA->getTarget();

    // Process annotations
    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      const Expr *LengthExpr;
      if (isSecureBufferAttr(*APtr, LengthExpr)) {
        checkSecureBufferAttr(
            Call, C,
            createSValForParamExpr(C.getSValBuilder(), C, Call, Target),
            Target->getType(), LengthExpr);
      }
    }
  }
}

void SecureBufferChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  ProgramStateRef state = C.getState();

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
      const Expr *LengthExpr;
      if (isSecureBufferAttr(*APtr, LengthExpr)) {
        state = assumeSecureBufferAttr(
            C, state,
            createSValForParamExpr(C.getSValBuilder(), C, Call, Target),
            Target->getType(), LengthExpr);
      }
    }
  }

  if (state != C.getState())
    C.addTransition(state);
}

// Upon accessing a memory location, check if it is within the secure-buffer
// boundaries.
void SecureBufferChecker::checkLocation(SVal Location, bool IsLoad,
                                        const Stmt *S,
                                        CheckerContext &C) const {
  SValBuilder &SVB = C.getSValBuilder();
  ProgramStateRef state = C.getState();

  const LocationInfo &rawOffset =
      LocationInfo::computeOffset(state, SVB, Location);
  const SubRegion *SR = rawOffset.getRegion();
  if (!SR) {
    reportBug(C, UnknownLength, S);
    return;
  }

  DefinedOrUnknownSVal Length = SR->getExtent(SVB);
  DefinedOrUnknownSVal Offset = rawOffset.getByteOffset();

  ProgramStateRef StInBound = state->assumeInBound(Offset, Length, true);
  ProgramStateRef StOutBound = state->assumeInBound(Offset, Length, false);

  if (StOutBound && !StInBound) {
    reportBug(C, AccessIsOutOfBounds, S);
  } else if ((bool)StInBound == (bool)StOutBound) {
    reportBug(C, AccessMayOutOfBounds, S);
  }
}

void SecureBufferChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  const auto *LCtx = C.getLocationContext();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  // Attributes on function parameters
  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (SecureBufferAttr *SBA = PVD->getAttr<SecureBufferAttr>()) {
      const MemRegion *MR = state->getRegion(PVD, LCtx);
      SVal TargetVal =
          state->getSVal(MR, PVD->getType()).castAs<DefinedOrUnknownSVal>();
      state = assumeSecureBufferAttr(C, state, TargetVal, PVD->getType(),
                                     SBA->getLength());
    }
  }

  // Process secure_c_in annotations, if any
  for (auto *SCInA : FD->specific_attrs<SecureCInAttr>()) {
    Expr *Target = SCInA->getTarget();
    auto *DRE = cast<DeclRefExpr>(Target);
    auto *PVD = cast<ParmVarDecl>(DRE->getDecl());

    // Process annotations
    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      const Expr *LengthExpr;
      if (isSecureBufferAttr(*APtr, LengthExpr)) {
        state = assumeSecureBufferAttr(
            C, state,
            getValueForExpr(C, state, C.getSValBuilder(), Target, LCtx),
            Target->getType(), LengthExpr);
      }
    }
  }

  if (state != C.getState())
    C.addTransition(state);
}

// void SecureBufferChecker::checkEndFunction(const ReturnStmt *S,
//                                            CheckerContext &C) const {
//   ProgramStateRef state = C.getState();
//   const auto *LCtx = C.getLocationContext();
//   const auto *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
//   if (!FD)
//     return;

//   // Process secure_c_out annotations, if any
//   for (auto *SCInA : FD->specific_attrs<SecureCOutAttr>()) {
//     const Expr *Target = SCInA->getTarget();
//     // Replace DRE to function with return expression
//     if (isa<DeclRefExpr>(Target)) {
//       auto *DRE = cast<DeclRefExpr>(Target);
//       if (isa<FunctionDecl>(DRE->getDecl())) {
//         llvm::errs() << "GOT A FUNCDECL\n";
//         Target = S->getRetValue();
//       }
//     }
//     auto *DRE = cast<DeclRefExpr>(Target);
//     auto *PVD = cast<ParmVarDecl>(DRE->getDecl());

//     // Process annotations
//     for (Expr **APtr = SCInA->annotations_begin();
//          APtr < SCInA->annotations_end(); APtr++) {
//       const Expr *LengthExpr;
//       if (isSecureBufferAttr(*APtr, LengthExpr)) {
//         state = assumeSecureBufferAttr(C, state, PVD, LengthExpr);
//       }
//     }
//   }

//   if (state != C.getState())
//     C.addTransition(state);
// }

// Ensure that the length expressions are kept live
void SecureBufferChecker::checkLiveSymbols(ProgramStateRef state,
                                           SymbolReaper &SR) const {
  // Mark all symbols in our secure-buffer length map as valid
  SecureBufferLengthTy Entries = state->get<SecureBufferLength>();
  for (SecureBufferLengthTy::iterator I = Entries.begin(), E = Entries.end();
       I != E; ++I) {
    SVal Len = I.getData();
    for (SymExpr::symbol_iterator si = Len.symbol_begin(),
                                  se = Len.symbol_end();
         si != se; ++si) {
      SR.markLive(*si); // Ensure any symbols used in the length are kept alive
    }
  }
}

// When a memory region is no longer live, remove the length from our list
void SecureBufferChecker::checkDeadSymbols(SymbolReaper &SR,
                                           CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  SecureBufferLengthTy Entries = state->get<SecureBufferLength>();
  if (Entries.isEmpty())
    return;

  SecureBufferLengthTy::Factory &F = state->get_context<SecureBufferLength>();
  for (SecureBufferLengthTy::iterator I = Entries.begin(), E = Entries.end();
       I != E; ++I) {
    const MemRegion *MR = I.getKey();
    if (!SR.isLiveRegion(MR)) {
      Entries = F.remove(Entries, I.getKey());
    }
  }

  state = state->set<SecureBufferLength>(Entries);
  C.addTransition(state);
}

LLVM_DUMP_METHOD void SecureBufferChecker::dump(ProgramStateRef state) const {
  llvm::errs() << "SecureBuffer Lengths:\n";
  SecureBufferLengthTy Entries = state->get<SecureBufferLength>();
  for (SecureBufferLengthTy::iterator I = Entries.begin(), E = Entries.end();
       I != E; ++I) {
    const MemRegion *MR = I.getKey();
    SVal Len = I.getData();
    llvm::errs() << "  ";
    MR->dump();
    llvm::errs() << ": ";
    Len.dump();
    llvm::errs() << "\n";
  }
}

void ento::registerSecureBufferChecker(CheckerManager &mgr) {
  mgr.registerChecker<SecureBufferChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterSecureBufferChecker(const LangOptions &LO) {
  return true;
}

// Returns true and sets LengthExpr if AttrExpr is a secure-buffer annotation
bool SecureBufferChecker::isSecureBufferAttr(const Expr *AttrExpr,
                                             const Expr *&LengthExpr) const {
  if (const auto *CE = dyn_cast<CallExpr>(AttrExpr)) {
    if (const FunctionDecl *FD = CE->getDirectCallee()) {
      const IdentifierInfo *II = FD->getIdentifier();
      if (II && II->getName().equals("secure_buffer")) {
        LengthExpr = CE->getArg(0);
        return true;
      }
    }
  }

  return false;
}

ProgramStateRef SecureBufferChecker::assumeSecureBufferAttr(
    CheckerContext &C, ProgramStateRef state, SVal TargetVal,
    QualType TargetType, const Expr *LengthExpr) const {
  SValBuilder &SVB = C.getSValBuilder();
  const auto *LCtx = C.getLocationContext();
  const MemRegion *MR = TargetVal.getAsRegion();
  assert(MR);
  const SubRegion *SR = dyn_cast<SubRegion>(MR);
  assert(SR);
  DefinedOrUnknownSVal SBLength =
      getValueForExpr(C, state, SVB, LengthExpr, LCtx);
  assert(!SBLength.isUnknown());
  SVal SBLengthBytes =
      elementCountToByteCount(C, SBLength, TargetType->getPointeeType());
  state = state->set<SecureBufferLength>(MR, SBLengthBytes);
  DefinedOrUnknownSVal extentMatchesSize = SVB.evalEQ(
      state, SR->getExtent(SVB), SBLengthBytes.castAs<DefinedSVal>());
  return state->assume(extentMatchesSize, true);
}

void SecureBufferChecker::checkSecureBufferAttr(const CallEvent &Call,
                                                CheckerContext &C,
                                                SVal TargetVal,
                                                QualType TargetType,
                                                const Expr *LExpr) const {
  SValBuilder &SVB = C.getSValBuilder();
  ProgramStateRef state = C.getState();
  // Target is known to be a pointer type already, so this is safe
  QualType elemType = TargetType->getPointeeType();
  DefinedOrUnknownSVal Length = getBufferLength(C, SVB, TargetVal);
  if (Length.isUnknown()) {
    reportBug(C, MayBreakConstraint, Call.getOriginExpr());
    return;
  }

  SVal ReqLengthElem = createSValForParamExpr(SVB, C, Call, LExpr);
  SVal ReqLength = elementCountToByteCount(C, ReqLengthElem, elemType);
  SVal InRange =
      SVB.evalBinOp(state, BO_GE, Length, ReqLength, SVB.getArrayIndexType());

  ProgramStateRef StInBound, StOutBound;
  std::tie(StInBound, StOutBound) =
      state->assume(InRange.castAs<DefinedOrUnknownSVal>());

  if (StOutBound && !StInBound) {
    reportBug(C, BreaksConstraint, Call.getOriginExpr());
  } else if ((bool)StInBound == (bool)StOutBound) {
    reportBug(C, MayBreakConstraint, Call.getOriginExpr());
  }
}
