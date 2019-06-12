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
    : public Checker<check::PreCall, check::Location, check::BeginFunction,
                     check::LiveSymbols, check::DeadSymbols> {
  mutable std::unique_ptr<BugType> BT;

  enum SB_Kind {
    AccessIsOutOfBounds,
    AccessMayOutOfBounds,
    BreaksConstraint,
    MayBreakConstraint,
    UnknownLength
  };

  void reportBug(CheckerContext &C, SB_Kind Kind, const Stmt *S) const;

  SVal getLengthForRegion(CheckerContext &C, ProgramStateRef &state,
                          const Expr *E, const MemRegion *MR) const;
  SVal getLengthForParam(CheckerContext &C, ProgramStateRef &state,
                         const Expr *DRE, const ParmVarDecl *PVD) const;
  DefinedOrUnknownSVal getBufferLength(CheckerContext &C, SValBuilder &SVB,
                                       SVal Val) const;

public:
  static void *getTag() {
    static int tag;
    return &tag;
  }

  // Process arguments at call-sites
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal location, bool isLoad, const Stmt *S,
                     CheckerContext &C) const;
  void checkBeginFunction(CheckerContext &C) const;

  void checkLiveSymbols(ProgramStateRef state, SymbolReaper &SR) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;

  void dump(ProgramStateRef state) const;
};

// Used to compute the base and offset of a memory location
class LocationInfo {
private:
  const SubRegion *BaseRegion;
  SVal ByteOffset;

  LocationInfo() : BaseRegion(nullptr), ByteOffset(UnknownVal()) {}

public:
  LocationInfo(const SubRegion *Base, SVal Offset)
      : BaseRegion(Base), ByteOffset(Offset) {}

  NonLoc getByteOffset() const { return ByteOffset.castAs<NonLoc>(); }
  const SubRegion *getRegion() const { return BaseRegion; }

  static LocationInfo computeOffset(ProgramStateRef State, SValBuilder &SVB,
                                    SVal Location);

  void dump() const;
  void dumpToStream(raw_ostream &OS) const;
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

  SValBuilder &SVB = C.getSValBuilder();
  ProgramStateRef state = C.getState();

  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (SecureBufferAttr *SBA = PVD->getAttr<SecureBufferAttr>()) {
      // Param is known to be a pointer type already, so this is safe
      QualType elemType = PVD->getType()->getPointeeType();
      SVal ArgVal = Call.getArgSVal(i);
      DefinedOrUnknownSVal Length = getBufferLength(C, SVB, ArgVal);
      if (Length.isUnknown()) {
        reportBug(C, MayBreakConstraint, Call.getArgExpr(i));
        continue;
      }

      const Expr *ReqLengthExpr = SBA->getLength();
      SVal ReqLengthElem = createSValForParamExpr(SVB, C, Call, ReqLengthExpr);
      SVal ReqLength = elementCountToByteCount(C, ReqLengthElem, elemType);
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

// Scale a base value by a scaling factor, and return the scaled
// value as an SVal.  Used by 'computeOffset'.
static inline SVal scaleValue(ProgramStateRef State, NonLoc BaseVal,
                              CharUnits Scaling, SValBuilder &SVB) {
  return SVB.evalBinOpNN(State, BO_Mul, BaseVal,
                         SVB.makeArrayIndex(Scaling.getQuantity()),
                         SVB.getArrayIndexType());
}

/// Compute a raw byte offset from a base region.  Used for array bounds
/// checking.
LocationInfo LocationInfo::computeOffset(ProgramStateRef State,
                                         SValBuilder &SVB, SVal Location) {
  const MemRegion *Region = Location.getAsRegion();
  SVal Offset = SVB.makeArrayIndex(0);

  if (Region->getKind() == MemRegion::ElementRegionKind) {
    const ElementRegion *ElemReg = cast<ElementRegion>(Region);
    SVal Index = ElemReg->getIndex();
    if (!Index.getAs<NonLoc>())
      return LocationInfo();

    QualType ElemType = ElemReg->getElementType();

    // If the element is an incomplete type, go no further.
    if (ElemType->isIncompleteType())
      return LocationInfo();

    // Set the offset.
    Offset = scaleValue(State, Index.castAs<NonLoc>(),
                        SVB.getContext().getTypeSizeInChars(ElemType), SVB);

    // If we cannot determine the offset, return an invalid object
    if (Offset.isUnknownOrUndef())
      return LocationInfo();

    Region = ElemReg->getSuperRegion();
  }

  if (const SubRegion *SubReg = dyn_cast<SubRegion>(Region)) {
    return LocationInfo(SubReg, Offset);
  }

  return LocationInfo();
}

static DefinedOrUnknownSVal getValueForExpr(ProgramStateRef state,
                                            SValBuilder &SVB, const Expr *E,
                                            const LocationContext *Loc) {
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    return SVB.makeIntVal(IL);
  } else if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const ParmVarDecl *PVD =
            dyn_cast_or_null<ParmVarDecl>(DRE->getDecl())) {
      const MemRegion *Param = state->getRegion(PVD, Loc);
      return state->getSVal(Param, PVD->getType())
          .castAs<DefinedOrUnknownSVal>();
    }
    return UnknownVal();
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    return SVB
        .evalBinOp(state, BO->getOpcode(),
                   getValueForExpr(state, SVB, BO->getLHS(), Loc),
                   getValueForExpr(state, SVB, BO->getRHS(), Loc),
                   BO->getType())
        .castAs<DefinedOrUnknownSVal>();
  } else if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    return SVB
        .evalCast(getValueForExpr(state, SVB, CE->getSubExpr(), Loc),
                  CE->getType(), CE->getSubExpr()->getType())
        .castAs<DefinedOrUnknownSVal>();
  }

  return UnknownVal();
}

SVal SecureBufferChecker::getLengthForRegion(CheckerContext &C,
                                             ProgramStateRef &state,
                                             const Expr *E,
                                             const MemRegion *MR) const {
  // If we already have a length recorded for this buffer, use it
  const SVal *Recorded = state->get<SecureBufferLength>(MR);
  if (Recorded)
    return *Recorded;

  // Else, create a new symbol and add it to the state
  SValBuilder &SVB = C.getSValBuilder();
  QualType SizeTy = SVB.getContext().getSizeType();
  SVal Length = SVB.getMetadataSymbolVal(
      getTag(), MR, E, SizeTy, C.getLocationContext(), C.blockCount());

  if (const SubRegion *SR = dyn_cast<SubRegion>(MR)) {
    DefinedOrUnknownSVal extentEqualsMetadata =
        SVB.evalEQ(state, SR->getExtent(SVB), Length)
            .castAs<DefinedOrUnknownSVal>();
    state = state->assume(extentEqualsMetadata, true);
  }

  state = state->set<SecureBufferLength>(MR, Length);
  return Length;
}

SVal SecureBufferChecker::getLengthForParam(CheckerContext &C,
                                            ProgramStateRef &state,
                                            const Expr *DRE,
                                            const ParmVarDecl *PVD) const {
  const LocationContext *LCtx = C.getLocationContext();

  const MemRegion *MR = state->getRegion(PVD, LCtx);
  SVal MRSVal = state->getSVal(MR);
  MR = MRSVal.getAsRegion();
  if (!MR) {
    return UndefinedVal();
  }
  return getLengthForRegion(C, state, DRE, MR);
}

void SecureBufferChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  SValBuilder &SVB = C.getSValBuilder();
  const auto *LCtx = C.getLocationContext();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  // Attributes on function parameters
  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *PVD = FD->getParamDecl(i);

    if (SecureBufferAttr *SBA = PVD->getAttr<SecureBufferAttr>()) {
      SVal LengthVal = getLengthForParam(C, state, SBA->getBuffer(), PVD);
      DefinedOrUnknownSVal SBLength =
          getValueForExpr(state, SVB, SBA->getLength(), LCtx);
      assert(!SBLength.isUnknown());
      SVal SBLengthVal = SBLength;
      const RangeSet *RS =
          state->get<ConstraintRange>(SBLengthVal.getAsSymbol());
      if (RS) {
        state = state->set<ConstraintRange>(LengthVal.getAsSymbol(), *RS);
      }

      DefinedOrUnknownSVal extentMatchesSize =
          SVB.evalEQ(state, LengthVal.castAs<DefinedSVal>(),
                     SBLengthVal.castAs<DefinedSVal>());
      state = state->assume(extentMatchesSize, true);
    }
  }

  C.addTransition(state);
}

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
      SR.markInUse(*si);
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
