#include "clang/StaticAnalyzer/Checkers/SecureCCommon.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

SVal createSValForParamExpr(SValBuilder &SVB, CheckerContext &C,
                            const CallEvent &Call, const Expr *E) {
  if (const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(E)) {
    return SVB.makeIntVal(IL);
  } else if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (const ParmVarDecl *PVD = dyn_cast_or_null<ParmVarDecl>(DRE->getDecl()))
      return Call.getArgSVal(PVD->getFunctionScopeIndex());

    // References to other decls are not allowed
    return UndefinedVal();
  } else if (const BinaryOperator *BO = dyn_cast<BinaryOperator>(E)) {
    return SVB.evalBinOp(C.getState(), BO->getOpcode(),
                         createSValForParamExpr(SVB, C, Call, BO->getLHS()),
                         createSValForParamExpr(SVB, C, Call, BO->getRHS()),
                         BO->getType());
  } else if (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
    return SVB.evalCast(createSValForParamExpr(SVB, C, Call, CE->getSubExpr()),
                        CE->getType(), CE->getSubExpr()->getType());
  }

  return UndefinedVal();
}
