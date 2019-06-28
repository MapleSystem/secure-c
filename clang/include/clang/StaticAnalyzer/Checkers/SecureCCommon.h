// SecureCCommon.h - Common code shared by Secure-C checkers -------*- C++ -*-//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines code that is shared between multiple Secure-C checkers.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_STATICANALYZER_CHECKERS_SECURECCOMMON_H
#define LLVM_CLANG_STATICANALYZER_CHECKERS_SECURECCOMMON_H

#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"

using namespace clang;
using namespace ento;

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

// Given a simple expression, create an SVal for it
DefinedOrUnknownSVal getValueForExpr(CheckerContext &C, ProgramStateRef State,
                                     SValBuilder &SVB, const Expr *E,
                                     const LocationContext *Loc,
                                     const CallEvent *Call = NULL);

// Given an expression in terms of the function parameters, create an SVal
// for it, replacing references to the parameters with the corresponding
// argument expressions.
SVal createSValForParamExpr(SValBuilder &SVB, CheckerContext &C,
                            const CallEvent &Call, const Expr *E);

#endif // LLVM_CLANG_STATICANALYZER_CHECKERS_SECURECCOMMON_H
