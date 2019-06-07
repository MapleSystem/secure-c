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
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"

using namespace clang;
using namespace ento;

// Given an expression in terms of the function parameters, create an SVal
// for it, replacing references to the parameters with the corresponding
// argument expressions.
SVal createSValForParamExpr(SValBuilder &SVB, CheckerContext &C,
                            const CallEvent &Call, const Expr *E);

#endif // LLVM_CLANG_STATICANALYZER_CHECKERS_SECURECCOMMON_H
