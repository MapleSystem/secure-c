#include "clang/StaticAnalyzer/Checkers/SecureCCommon.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

#ifndef DEBUG_TYPE
#define DEBUG_TYPE "Secure-C Common"
#endif

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

SVal createSValForParamExpr(SValBuilder &SVB, CheckerContext &C,
                            const CallEvent &Call, const Expr *E) {
  return getValueForExpr(C, C.getState(), C.getSValBuilder(), E,
                         C.getLocationContext(), &Call);
}

static std::pair<const SubRegion *, Store>
getBaseRegion(CheckerContext &C, ProgramStateRef State, const Expr *E,
              const LocationContext *Loc, const CallEvent *Call) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (Call) {
      if (const ParmVarDecl *PVD =
              dyn_cast_or_null<ParmVarDecl>(DRE->getDecl())) {
        SVal ArgSVal = Call->getArgSVal(PVD->getFunctionScopeIndex());
        if (auto LV = ArgSVal.getAs<nonloc::LazyCompoundVal>()) {
          const LazyCompoundValData *D = LV->getCVData();
          return std::pair<const SubRegion *, Store>(D->getRegion(),
                                                     D->getStore());
        }
        return std::pair<const SubRegion *, Store>(
            dyn_cast<SubRegion>(ArgSVal.getAsRegion()), NULL);
      }
    }

    if (const VarDecl *VD = dyn_cast_or_null<VarDecl>(DRE->getDecl()))
      return std::pair<const SubRegion *, Store>(State->getRegion(VD, Loc),
                                                 NULL);
  } else if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    std::pair<const SubRegion *, Store> RSPair = getBaseRegion(
        C, State, ME->getBase()->IgnoreParenImpCasts(), Loc, Call);
    const SubRegion *SR = std::get<0>(RSPair);
    const FieldRegion *FR =
        C.getStoreManager().getRegionManager().getFieldRegion(
            dyn_cast<FieldDecl>(ME->getMemberDecl()), SR);
    return std::pair<const SubRegion *, Store>(FR, std::get<1>(RSPair));
  }

  return std::pair<const SubRegion *, Store>(NULL, NULL);
}

DefinedOrUnknownSVal getValueForExpr(CheckerContext &C, ProgramStateRef State,
                                     SValBuilder &SVB, const Expr *E,
                                     const LocationContext *Loc,
                                     const CallEvent *Call) {
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    return SVB.makeIntVal(IL);
  } else if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (Call) {
      if (const ParmVarDecl *PVD =
              dyn_cast_or_null<ParmVarDecl>(DRE->getDecl()))
        return Call->getArgSVal(PVD->getFunctionScopeIndex())
            .castAs<DefinedOrUnknownSVal>();
    }

    if (const VarDecl *VD = dyn_cast_or_null<VarDecl>(DRE->getDecl())) {
      const MemRegion *MR = State->getRegion(VD, Loc);
      return State->getSVal(MR, VD->getType()).castAs<DefinedOrUnknownSVal>();
    }
    return UnknownVal();
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    return SVB
        .evalBinOp(State, BO->getOpcode(),
                   getValueForExpr(C, State, SVB, BO->getLHS(), Loc),
                   getValueForExpr(C, State, SVB, BO->getRHS(), Loc),
                   BO->getType())
        .castAs<DefinedOrUnknownSVal>();
  } else if (const MemberExpr *ME = dyn_cast<MemberExpr>(E)) {
    std::pair<const SubRegion *, Store> RSPair = getBaseRegion(
        C, State, ME->getBase()->IgnoreParenImpCasts(), Loc, Call);
    const SubRegion *SR = std::get<0>(RSPair);
    const ValueDecl *VD = ME->getMemberDecl();
    const FieldRegion *FR =
        C.getStoreManager().getRegionManager().getFieldRegion(
            cast<FieldDecl>(VD), SR);
    SVal Val = State->getSVal(FR, ME->getType());
    if (Val.isUndef()) {
      const SVal &V = C.getStoreManager().getBinding(std::get<1>(RSPair),
                                                     loc::MemRegionVal(FR));
      return V.castAs<DefinedOrUnknownSVal>();
    }
    return Val.castAs<DefinedOrUnknownSVal>();
  } else if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    return SVB
        .evalCast(getValueForExpr(C, State, SVB, CE->getSubExpr(), Loc),
                  CE->getType(), CE->getSubExpr()->getType())
        .castAs<DefinedOrUnknownSVal>();
  } else if (const ParenExpr *PE = dyn_cast<ParenExpr>(E)) {
    return getValueForExpr(C, State, SVB, PE->getSubExpr(), Loc);
  }

  SVal Val = State->getSVal(E, Loc);
  if (!Val.isUndef())
    return Val.castAs<DefinedOrUnknownSVal>();

  llvm::errs() << "ERROR: Failed to get SVal for:\n";
  E->dump();
  return UnknownVal();
}
