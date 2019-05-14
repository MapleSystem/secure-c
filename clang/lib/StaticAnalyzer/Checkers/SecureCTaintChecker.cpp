//== SecureCTaintChecker.cpp ----------------------------------- -*- C++ -*--=//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This checker defines the attack surface for generic taint propagation.
//
// The taint information produced by it might be useful to other checkers. For
// example, checkers should report errors which involve tainted data more
// aggressively, even if the involved symbols are under constrained.
//
//===----------------------------------------------------------------------===//
#include "clang/AST/Attr.h"
#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include <climits>
#include <initializer_list>
#include <iostream>
#include <utility>
using namespace clang;
using namespace ento;

namespace {
class SecureCTaintChecker
    : public Checker<check::BeginFunction, check::PostStmt<CallExpr>,
                     check::PreStmt<CallExpr>,
                     check::PreStmt<ArraySubscriptExpr>,
                     check::PreStmt<MemberExpr>, check::PreStmt<BinaryOperator>,
                     check::PreStmt<UnaryOperator>, check::PreStmt<DeclStmt>,
                     check::BranchCondition> {
public:
  static void *getTag() {
    static int Tag;
    return &Tag;
  }

  void checkBeginFunction(CheckerContext &C) const;

  void checkPostStmt(const CallExpr *CE, CheckerContext &C) const;

  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;

  void checkPreStmt(const ArraySubscriptExpr *AE, CheckerContext &C) const;

  void checkPreStmt(const MemberExpr *ME, CheckerContext &C) const;

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;

  void checkPreStmt(const UnaryOperator *UO, CheckerContext &C) const;

  void checkPreStmt(const DeclStmt *D, CheckerContext &C) const;

  void checkBranchCondition(const Stmt *S, CheckerContext &C) const;

private:
  static const unsigned InvalidArgIndex = UINT_MAX;
  /// Denotes the return vale.
  static const unsigned ReturnValueIndex = UINT_MAX - 1;

  mutable std::unique_ptr<BugType> BT;
  void initBugType() const {
    if (!BT)
      BT.reset(new BugType(this, "Taint", "Secure-C"));
  }

  /// Catch taint related bugs. Check if tainted data is passed to a
  /// system call etc.
  bool checkPre(const CallExpr *CE, CheckerContext &C) const;

  ProgramStateRef addSecureCTaintAfter(const CallExpr *CE, const FunctionDecl *FDecl,
                          CheckerContext &C) const;

  /// Add taint sources on a pre-visit.
  void addSourcesPre(const CallExpr *CE, CheckerContext &C) const;

  /// Propagate taint generated at pre-visit.
  bool propagateFromPre(const CallExpr *CE, CheckerContext &C) const;

  /// Add taint sources on a post visit.
  void addSourcesPost(const CallExpr *CE, CheckerContext &C) const;

  /// Check if the region the expression evaluates to is the standard input,
  /// and thus, is tainted.
  static bool isStdin(const Expr *E, CheckerContext &C);

  /// Given a pointer argument, return the value it points to.
  static Optional<SVal> getPointedToSVal(CheckerContext &C, const Expr *Arg);

  /// Functions defining the attack surface.
  using FnCheck = ProgramStateRef (SecureCTaintChecker::*)(
      const CallExpr *, CheckerContext &C) const;
  ProgramStateRef postScanf(const CallExpr *CE, CheckerContext &C) const;
  ProgramStateRef postSocket(const CallExpr *CE, CheckerContext &C) const;
  ProgramStateRef postRetTaint(const CallExpr *CE, CheckerContext &C) const;

  /// Taint the scanned input if the file is tainted.
  ProgramStateRef preFscanf(const CallExpr *CE, CheckerContext &C) const;

  /// Check for CWE-134: Uncontrolled Format String.
  static const char MsgUncontrolledFormatString[];
  bool checkUncontrolledFormatString(const CallExpr *CE,
                                     CheckerContext &C) const;

  /// Check for:
  /// CERT/STR02-C. "Sanitize data passed to complex subsystems"
  /// CWE-78, "Failure to Sanitize Data into an OS Command"
  static const char MsgSanitizeSystemArgs[];
  bool checkSystemCall(const CallExpr *CE, StringRef Name,
                       CheckerContext &C) const;

  /// Check if tainted data is used as a buffer size ins strn.. functions,
  /// and allocators.
  static const char MsgTaintedBufferSize[];
  bool checkTaintedBufferSize(const CallExpr *CE, const FunctionDecl *FDecl,
                              CheckerContext &C) const;

  static const char MsgTaintedTrustArguments[];
  bool checkTrustAnnotatedFunctionCall(const CallExpr *CE,
                                       const FunctionDecl *FDecl,
                                       CheckerContext &C) const;

  static const char MsgTaintedArrayIndexing[];
  static const char MsgTaintedArray[];
  static const char MsgTaintedPointerDereference[];
  static const char MsgTaintedPointerAddressOf[];
  static const char MsgTaintedCondition[];
  static const char MsgTaintedIntegerArithmetic[];
  static const char MsgTaintedPointerArithmetic[];
  static const char MsgTaintedVariableLengthArraySize[];

  /// Generate a report if the expression is tainted or points to tainted data.
  bool generateReportIfTainted(const Expr *E, const char Msg[],
                               CheckerContext &C) const;

  using ArgVector = SmallVector<unsigned, 2>;

  /// A struct used to specify taint propagation rules for a function.
  ///
  /// If any of the possible taint source arguments is tainted, all of the
  /// destination arguments should also be tainted. Use InvalidArgIndex in the
  /// src list to specify that all of the arguments can introduce taint. Use
  /// InvalidArgIndex in the dst arguments to signify that all the non-const
  /// pointer and reference arguments might be tainted on return. If
  /// ReturnValueIndex is added to the dst list, the return value will be
  /// tainted.
  struct TaintPropagationRule {
    enum class VariadicType { None, Src, Dst };

    /// List of arguments which can be taint sources and should be checked.
    ArgVector SrcArgs;
    /// List of arguments which should be tainted on function return.
    ArgVector DstArgs;
    /// Index for the first variadic parameter if exist.
    unsigned VariadicIndex;
    /// Show when a function has variadic parameters. If it has, it marks all
    /// of them as source or destination.
    VariadicType VarType;

    TaintPropagationRule()
        : VariadicIndex(InvalidArgIndex), VarType(VariadicType::None) {}

    TaintPropagationRule(std::initializer_list<unsigned> &&Src,
                         std::initializer_list<unsigned> &&Dst,
                         VariadicType Var = VariadicType::None,
                         unsigned VarIndex = InvalidArgIndex)
        : SrcArgs(std::move(Src)), DstArgs(std::move(Dst)),
          VariadicIndex(VarIndex), VarType(Var) {}

    /// Get the propagation rule for a given function.
    static TaintPropagationRule
    getTaintPropagationRule(const FunctionDecl *FDecl, StringRef Name,
                            CheckerContext &C);

    void addSrcArg(unsigned A) { SrcArgs.push_back(A); }
    void addDstArg(unsigned A) { DstArgs.push_back(A); }

    bool isNull() const {
      return SrcArgs.empty() && DstArgs.empty() &&
             VariadicType::None == VarType;
    }

    bool isDestinationArgument(unsigned ArgNum) const {
      return (llvm::find(DstArgs, ArgNum) != DstArgs.end());
    }

    static bool isTaintedOrPointsToTainted(const Expr *E, ProgramStateRef State,
                                           CheckerContext &C) {
      if (State->isTainted(E, C.getLocationContext()) || isStdin(E, C))
        return true;

      if (!E->getType().getTypePtr()->isPointerType())
        return false;

      Optional<SVal> V = getPointedToSVal(C, E);
      return (V && State->isTainted(*V));
    }

    /// Pre-process a function which propagates taint according to the
    /// taint rule.
    ProgramStateRef process(const CallExpr *CE, CheckerContext &C) const;
  };
};

const unsigned SecureCTaintChecker::ReturnValueIndex;
const unsigned SecureCTaintChecker::InvalidArgIndex;

const char SecureCTaintChecker::MsgUncontrolledFormatString[] =
    "Untrusted data is used as a format string "
    "(CWE-134: Uncontrolled Format String)";

const char SecureCTaintChecker::MsgSanitizeSystemArgs[] =
    "Untrusted data is passed to a system call "
    "(CERT/STR02-C. Sanitize data passed to complex subsystems)";

const char SecureCTaintChecker::MsgTaintedBufferSize[] =
    "Untrusted data is used to specify the buffer size "
    "(CERT/STR31-C. Guarantee that storage for strings has sufficient space "
    "for character data and the null terminator)";

const char SecureCTaintChecker::MsgTaintedTrustArguments[] =
    "Untrusted data is passed to a trusted parameter in the call";

const char SecureCTaintChecker::MsgTaintedArrayIndexing[] =
    "Possible out-of-bound access due to untrusted index variable";

const char SecureCTaintChecker::MsgTaintedArray[] =
    "Possible null dereference or out-of-bound access due to untrusted array";

const char SecureCTaintChecker::MsgTaintedPointerDereference[] =
    "Possible null or dangerous dereference due to untrusted pointer variable";

const char SecureCTaintChecker::MsgTaintedPointerAddressOf[] =
    "Possibly a dangerous AddressOf operation due to untrusted pointer "
    "variable";

const char SecureCTaintChecker::MsgTaintedCondition[] =
    "Possible to take wrong branch or cause infinite/long loop due to "
    "untrusted variable in the branch/loop terminating condition";

const char SecureCTaintChecker::MsgTaintedIntegerArithmetic[] =
    "Possible integer overflow due to untrusted operand variable";

const char SecureCTaintChecker::MsgTaintedPointerArithmetic[] =
    "Possibly a dangerous pointer arithmetic operation due to untrusted "
    "pointer";

const char SecureCTaintChecker::MsgTaintedVariableLengthArraySize[] =
    "Possible allocation of wrong size memory in variable length array due to "
    "untrusted size variable";

} // end of anonymous namespace

/// A set which is used to pass information from call pre-visit instruction
/// to the call post-visit. The values are unsigned integers, which are either
/// ReturnValueIndex, or indexes of the pointer/reference argument, which
/// points to data, which should be tainted on return.
REGISTER_SET_WITH_PROGRAMSTATE(TaintArgsOnPostVisit, unsigned)
REGISTER_SET_WITH_PROGRAMSTATE(TrustedSymbols, SymbolRef)

SecureCTaintChecker::TaintPropagationRule
SecureCTaintChecker::TaintPropagationRule::getTaintPropagationRule(
    const FunctionDecl *FDecl, StringRef Name, CheckerContext &C) {
  // TODO: Currently, we might lose precision here: we always mark a return
  // value as tainted even if it's just a pointer, pointing to tainted data.

  // Check for exact name match for functions without builtin substitutes.
  TaintPropagationRule Rule =
      llvm::StringSwitch<TaintPropagationRule>(Name)
          .Case("atoi", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("atol", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("atoll", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("getc", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("fgetc", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("getc_unlocked", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("getw", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("toupper", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("tolower", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("strchr", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("strrchr", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Case("read", TaintPropagationRule({0, 2}, {1, ReturnValueIndex}))
          .Case("pread",
                TaintPropagationRule({0, 1, 2, 3}, {1, ReturnValueIndex}))
          .Case("gets", TaintPropagationRule({}, {0, ReturnValueIndex}))
          .Case("fgets", TaintPropagationRule({2}, {0, ReturnValueIndex}))
          .Case("getline", TaintPropagationRule({2}, {0}))
          .Case("getdelim", TaintPropagationRule({3}, {0}))
          .Case("fgetln", TaintPropagationRule({0}, {ReturnValueIndex}))
          .Default(TaintPropagationRule());

  if (!Rule.isNull())
    return Rule;

  // Check if it's one of the memory setting/copying functions.
  // This check is specialized but faster then calling isCLibraryFunction.
  unsigned BId = 0;
  if ((BId = FDecl->getMemoryFunctionKind()))
    switch (BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
    case Builtin::BIstrncat:
      return TaintPropagationRule({1, 2}, {0, ReturnValueIndex});
    case Builtin::BIstrlcpy:
    case Builtin::BIstrlcat:
      return TaintPropagationRule({1, 2}, {0});
    case Builtin::BIstrndup:
      return TaintPropagationRule({0, 1}, {ReturnValueIndex});

    default:
      break;
    };

  // Process all other functions which could be defined as builtins.
  if (Rule.isNull()) {
    if (C.isCLibraryFunction(FDecl, "snprintf"))
      return TaintPropagationRule({1}, {0, ReturnValueIndex}, VariadicType::Src,
                                  3);
    else if (C.isCLibraryFunction(FDecl, "sprintf"))
      return TaintPropagationRule({}, {0, ReturnValueIndex}, VariadicType::Src,
                                  2);
    else if (C.isCLibraryFunction(FDecl, "strcpy") ||
             C.isCLibraryFunction(FDecl, "stpcpy") ||
             C.isCLibraryFunction(FDecl, "strcat"))
      return TaintPropagationRule({1}, {0, ReturnValueIndex});
    else if (C.isCLibraryFunction(FDecl, "bcopy"))
      return TaintPropagationRule({0, 2}, {1});
    else if (C.isCLibraryFunction(FDecl, "strdup") ||
             C.isCLibraryFunction(FDecl, "strdupa"))
      return TaintPropagationRule({0}, {ReturnValueIndex});
    else if (C.isCLibraryFunction(FDecl, "wcsdup"))
      return TaintPropagationRule({0}, {ReturnValueIndex});
  }

  // Skipping the following functions, since they might be used for cleansing
  // or smart memory copy:
  // - memccpy - copying until hitting a special character.

  return TaintPropagationRule();
}

void SecureCTaintChecker::checkBeginFunction(CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  const auto *LCtx = C.getLocationContext();
  const auto *FD = dyn_cast_or_null<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  for (auto *SCInA : FD->specific_attrs<SecureCInAttr>()) {
    Expr *Target = SCInA->getTarget();
    bool PointeeOnly = false;

    DeclRefExpr *DRE;
    if (const auto *UO = dyn_cast<UnaryOperator>(Target)) {
      DRE = cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts());
      PointeeOnly = true;
    } else {
      DRE = cast<DeclRefExpr>(Target);
    }

    ParmVarDecl *PVD = cast<ParmVarDecl>(DRE->getDecl());
    // Process annotations
    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      Expr *AExpr = *APtr;
      if (isa<StringLiteral>(AExpr)) {
        StringLiteral *AL = cast<StringLiteral>(AExpr);
        if (AL->getString().equals("untrusted")) {
          Loc ParamLoc = State->getLValue(PVD, LCtx);
          if (PointeeOnly) {
            QualType ParmTy = PVD->getType().getCanonicalType();
            QualType ValTy = ParmTy->getPointeeType();
            auto ParamPointeeValue =
                State->getSVal(ParamLoc, ValTy).getAs<DefinedOrUnknownSVal>();
            if (!ParamPointeeValue)
              continue;
            State = State->addTaint(*ParamPointeeValue);
          } else {
            auto ParamValue = State->getSVal(ParamLoc, PVD->getType())
                                  .getAs<DefinedOrUnknownSVal>();
            if (!ParamValue)
              continue;
            State = State->addTaint(*ParamValue);
          }
        } else if (AL->getString().equals("trusted")) {
          // To be handled
        }
      }
    }
  }
  if (State != C.getState()) {
    C.addTransition(State);
  }
}

void SecureCTaintChecker::checkPreStmt(const CallExpr *CE,
                                       CheckerContext &C) const {
  // Check for errors first.
  if (checkPre(CE, C))
    return;

  // Add taint second.
  addSourcesPre(CE, C);
}

void SecureCTaintChecker::checkPreStmt(const ArraySubscriptExpr *AE,
                                       CheckerContext &C) const {
  if (generateReportIfTainted(AE->getBase(), MsgTaintedArray, C))
    return;
  if (generateReportIfTainted(AE->getIdx(), MsgTaintedArrayIndexing, C))
    return;
}

void SecureCTaintChecker::checkPreStmt(const MemberExpr *ME,
                                       CheckerContext &C) const {
  // TODO: Not sure if we need to skip non-arrow access?
  generateReportIfTainted(ME->getBase(), MsgTaintedPointerDereference, C);
}

void SecureCTaintChecker::checkPreStmt(const BinaryOperator *BO,
                                       CheckerContext &C) const {
  BinaryOperatorKind OpKind = BO->getOpcode();

  if (BO->isAdditiveOp() || OpKind == BO_AddAssign || OpKind == BO_SubAssign) {

    const Expr *Lhs = BO->getLHS();
    const Expr *Rhs = BO->getRHS();

    if (Lhs->getType()->isPointerType() &&
        generateReportIfTainted(Lhs, MsgTaintedPointerArithmetic, C)) {
      return;
    }
    if (Rhs->getType()->isPointerType() &&
        generateReportIfTainted(Rhs, MsgTaintedPointerArithmetic, C)) {
      return;
    }
  }

  if (BO->isAdditiveOp() || BO->isMultiplicativeOp() || BO->isShiftOp() ||
      BO->isShiftAssignOp() || BO->isBitwiseOp()) {

    const Expr *Lhs = BO->getLHS();
    const Expr *Rhs = BO->getRHS();

    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Lhs->IgnoreParenImpCasts())) {
      QualType IdxTy = DRE->getDecl()->getType();
      if (IdxTy->isIntegerType() &&
          generateReportIfTainted(Lhs, MsgTaintedIntegerArithmetic, C))
        return;
    }

    if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Rhs->IgnoreParenImpCasts())) {
      QualType IdxTy = DRE->getDecl()->getType();
      if (IdxTy->isIntegerType() &&
          generateReportIfTainted(Rhs, MsgTaintedIntegerArithmetic, C))
        return;
    }
  }

  if (BO->isCompoundAssignmentOp()) {
    // TODO
    return;
  }

  if (BO->isComparisonOp()) {
    if (generateReportIfTainted(BO->getLHS(), MsgTaintedCondition, C))
      return;
    if (generateReportIfTainted(BO->getRHS(), MsgTaintedCondition, C))
      return;
  }
}

void SecureCTaintChecker::checkPreStmt(const UnaryOperator *UO,
                                       CheckerContext &C) const {
  if (UO->getOpcode() == UO_AddrOf) {
    generateReportIfTainted(UO->getSubExpr(), MsgTaintedPointerAddressOf, C);
  } else if (UO->getOpcode() == UO_Deref) {
    generateReportIfTainted(UO->getSubExpr(), MsgTaintedPointerDereference, C);
  } else if (UO->isIncrementDecrementOp()) {
    if (UO->getType()->isPointerType()) {
      generateReportIfTainted(UO->getSubExpr(), MsgTaintedPointerArithmetic, C);
    } else {
      generateReportIfTainted(UO->getSubExpr(), MsgTaintedIntegerArithmetic, C);
    }
  } else if (UO->isArithmeticOp()) {
    generateReportIfTainted(UO->getSubExpr(), MsgTaintedIntegerArithmetic, C);
  }
}

void SecureCTaintChecker::checkPreStmt(const DeclStmt *DS,
                                       CheckerContext &C) const {
  if (!DS->isSingleDecl())
    return;

  const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
  if (!VD)
    return;

  ASTContext &Ctx = C.getASTContext();
  const VariableArrayType *VLA = Ctx.getAsVariableArrayType(VD->getType());
  if (!VLA)
    return;

  // FIXME: Handle multi-dimensional VLAs.
  generateReportIfTainted(VLA->getSizeExpr(), MsgTaintedVariableLengthArraySize, C);
}

void SecureCTaintChecker::checkPostStmt(const CallExpr *CE,
                                        CheckerContext &C) const {
  if (propagateFromPre(CE, C))
    return;
  addSourcesPost(CE, C);
}

void SecureCTaintChecker::checkBranchCondition(const Stmt *S,
                                               CheckerContext &C) const {
  if (const ImplicitCastExpr *IE = dyn_cast<ImplicitCastExpr>(S)) {
    generateReportIfTainted(IE, MsgTaintedCondition, C);
  }
}

ProgramStateRef SecureCTaintChecker::addSecureCTaintAfter(
    const CallExpr *CE, const FunctionDecl *FDecl, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  bool PointeeOnly = false;
  for (auto *SCOutA : FDecl->specific_attrs<SecureCOutAttr>()) {
    Expr *Target = SCOutA->getTarget();
    DeclRefExpr *DRE;
    if (const auto *UO = dyn_cast<UnaryOperator>(Target)) {
      DRE = cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts());
      PointeeOnly = true;
    } else {
      DRE = cast<DeclRefExpr>(Target);
    }

    unsigned TI;
    if (isa<FunctionDecl>(DRE->getDecl())) {
      TI = ReturnValueIndex;
    } else {
      ParmVarDecl *PVD = cast<ParmVarDecl>(DRE->getDecl());
      TI = PVD->getFunctionScopeIndex();
    }

    // Process annotations
    for (Expr **APtr = SCOutA->annotations_begin();
         APtr < SCOutA->annotations_end(); APtr++) {
      Expr *AExpr = *APtr;
      if (isa<StringLiteral>(AExpr)) {
        StringLiteral *AL = cast<StringLiteral>(AExpr);
        if (AL->getString().equals("untrusted")) {
          if (TI == ReturnValueIndex) {
            State = State->addTaint(CE, C.getLocationContext());
          } else {
            const Expr *Arg = CE->getArg(TI);
            // Get the pointee SVal and taint it
            Optional<SVal> V = getPointedToSVal(C, Arg);
            if (V)
              State = State->addTaint(*V);

            // Get the pointer SVal and taint it
            if (!PointeeOnly) {
              auto PointerSVal = C.getSVal(Arg).getAs<DefinedOrUnknownSVal>();
              if (!PointerSVal)
                continue;
              State = State->addTaint(*PointerSVal);
            }
          }
        } else if (AL->getString().equals("trusted")) {
          SVal Val;
          if (TI == ReturnValueIndex) {
            Val = C.getSVal(CE);
          } else {
            const Expr *Arg = CE->getArg(TI);
            Val = C.getSVal(Arg);
          }
          if (SymbolRef Sym = Val.getAsSymbol()) {
            State = State->add<TrustedSymbols>(Sym);
          }
        }
      }
    }
  }
  return State;
}

void SecureCTaintChecker::addSourcesPre(const CallExpr *CE,
                                        CheckerContext &C) const {
  ProgramStateRef State = nullptr;
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;

  // First, try generating a propagation rule for this function.
  TaintPropagationRule Rule =
      TaintPropagationRule::getTaintPropagationRule(FDecl, Name, C);
  if (!Rule.isNull()) {
    State = Rule.process(CE, C);
    if (!State)
      return;
    C.addTransition(State);
    return;
  }

  // Otherwise, check if we have custom pre-processing implemented.
  FnCheck evalFunction = llvm::StringSwitch<FnCheck>(Name)
                             .Case("fscanf", &SecureCTaintChecker::preFscanf)
                             .Default(nullptr);
  // Check and evaluate the call.
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return;
  C.addTransition(State);
}

bool SecureCTaintChecker::propagateFromPre(const CallExpr *CE,
                                           CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Depending on what was tainted at pre-visit, we determined a set of
  // arguments which should be tainted after the function returns. These are
  // stored in the state as TaintArgsOnPostVisit set.
  TaintArgsOnPostVisitTy TaintArgs = State->get<TaintArgsOnPostVisit>();
  if (TaintArgs.isEmpty())
    return false;

  for (unsigned ArgNum : TaintArgs) {
    // Special handling for the tainted return value.
    if (ArgNum == ReturnValueIndex) {
      State = State->addTaint(CE, C.getLocationContext());
      continue;
    }

    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    if (CE->getNumArgs() < (ArgNum + 1))
      return false;
    const Expr *Arg = CE->getArg(ArgNum);
    Optional<SVal> V = getPointedToSVal(C, Arg);
    if (V)
      State = State->addTaint(*V);
  }

  // Clear up the taint info from the state.
  State = State->remove<TaintArgsOnPostVisit>();

  if (State != C.getState()) {
    C.addTransition(State);
    return true;
  }
  return false;
}

void SecureCTaintChecker::addSourcesPost(const CallExpr *CE,
                                         CheckerContext &C) const {
  // Define the attack surface.
  // Set the evaluation function by switching on the callee name.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return;

  ProgramStateRef State = nullptr;
  // Taint arguments of untrusted function parameters
  State = addSecureCTaintAfter(CE, FDecl, C);
  if (State != nullptr) {
    C.addTransition(State);
    State = nullptr;
  }

  FnCheck evalFunction =
      llvm::StringSwitch<FnCheck>(Name)
          .Case("scanf", &SecureCTaintChecker::postScanf)
          // TODO: Add support for vfscanf & family.
          .Case("getchar", &SecureCTaintChecker::postRetTaint)
          .Case("getchar_unlocked", &SecureCTaintChecker::postRetTaint)
          .Case("getenv", &SecureCTaintChecker::postRetTaint)
          .Case("fopen", &SecureCTaintChecker::postRetTaint)
          .Case("fdopen", &SecureCTaintChecker::postRetTaint)
          .Case("freopen", &SecureCTaintChecker::postRetTaint)
          .Case("getch", &SecureCTaintChecker::postRetTaint)
          .Case("wgetch", &SecureCTaintChecker::postRetTaint)
          .Case("socket", &SecureCTaintChecker::postSocket)
          .Default(nullptr);

  // If the callee isn't defined, it is not of security concern.
  // Check and evaluate the call.
  if (evalFunction)
    State = (this->*evalFunction)(CE, C);
  if (!State)
    return;

  C.addTransition(State);
}

bool SecureCTaintChecker::checkPre(const CallExpr *CE,
                                   CheckerContext &C) const {

  if (checkUncontrolledFormatString(CE, C))
    return true;

  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl || FDecl->getKind() != Decl::Function)
    return false;

  StringRef Name = C.getCalleeName(FDecl);
  if (Name.empty())
    return false;

  if (checkSystemCall(CE, Name, C))
    return true;

  if (checkTaintedBufferSize(CE, FDecl, C))
    return true;

  if (checkTrustAnnotatedFunctionCall(CE, FDecl, C)) {
    return true;
  }

  return false;
}

Optional<SVal> SecureCTaintChecker::getPointedToSVal(CheckerContext &C,
                                                     const Expr *Arg) {
  ProgramStateRef State = C.getState();
  SVal AddrVal = C.getSVal(Arg->IgnoreParens());
  if (AddrVal.isUnknownOrUndef())
    return None;

  Optional<Loc> AddrLoc = AddrVal.getAs<Loc>();
  if (!AddrLoc)
    return None;

  QualType ArgTy = Arg->getType().getCanonicalType();
  if (!ArgTy->isPointerType())
    return None;

  QualType ValTy = ArgTy->getPointeeType();

  // Do not dereference void pointers. Treat them as byte pointers instead.
  // FIXME: we might want to consider more than just the first byte.
  if (ValTy->isVoidType())
    ValTy = C.getASTContext().CharTy;

  return State->getSVal(*AddrLoc, ValTy);
}

ProgramStateRef
SecureCTaintChecker::TaintPropagationRule::process(const CallExpr *CE,
                                                   CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  // Check for taint in arguments.
  bool IsTainted = false;
  for (unsigned ArgNum : SrcArgs) {
    if (ArgNum >= CE->getNumArgs())
      return State;
    if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(ArgNum), State, C)))
      break;
  }

  // Check for taint in variadic arguments.
  if (!IsTainted && VariadicType::Src == VarType) {
    // Check if any of the arguments is tainted
    for (unsigned int i = VariadicIndex; i < CE->getNumArgs(); ++i) {
      if ((IsTainted = isTaintedOrPointsToTainted(CE->getArg(i), State, C)))
        break;
    }
  }

  if (!IsTainted)
    return State;

  // Mark the arguments which should be tainted after the function returns.
  for (unsigned ArgNum : DstArgs) {
    // Should mark the return value?
    if (ArgNum == ReturnValueIndex) {
      State = State->add<TaintArgsOnPostVisit>(ReturnValueIndex);
      continue;
    }

    // Mark the given argument.
    assert(ArgNum < CE->getNumArgs());
    State = State->add<TaintArgsOnPostVisit>(ArgNum);
  }

  // Mark all variadic arguments tainted if present.
  if (VariadicType::Dst == VarType) {
    // For all pointer and references that were passed in:
    //   If they are not pointing to const data, mark data as tainted.
    //   TODO: So far we are just going one level down; ideally we'd need to
    //         recurse here.
    for (unsigned int i = VariadicIndex; i < CE->getNumArgs(); ++i) {
      const Expr *Arg = CE->getArg(i);
      // Process pointer argument.
      const Type *ArgTy = Arg->getType().getTypePtr();
      QualType PType = ArgTy->getPointeeType();
      if ((!PType.isNull() && !PType.isConstQualified()) ||
          (ArgTy->isReferenceType() && !Arg->getType().isConstQualified()))
        State = State->add<TaintArgsOnPostVisit>(i);
    }
  }

  return State;
}

// If argument 0 (file descriptor) is tainted, all arguments except for arg 0
// and arg 1 should get taint.
ProgramStateRef SecureCTaintChecker::preFscanf(const CallExpr *CE,
                                               CheckerContext &C) const {
  assert(CE->getNumArgs() >= 2);
  ProgramStateRef State = C.getState();

  // Check is the file descriptor is tainted.
  if (State->isTainted(CE->getArg(0), C.getLocationContext()) ||
      isStdin(CE->getArg(0), C)) {
    // All arguments except for the first two should get taint.
    for (unsigned int i = 2; i < CE->getNumArgs(); ++i)
      State = State->add<TaintArgsOnPostVisit>(i);
    return State;
  }

  return nullptr;
}

// If argument 0(protocol domain) is network, the return value should get taint.
ProgramStateRef SecureCTaintChecker::postSocket(const CallExpr *CE,
                                                CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (CE->getNumArgs() < 3)
    return State;

  SourceLocation DomLoc = CE->getArg(0)->getExprLoc();
  StringRef DomName = C.getMacroNameOrSpelling(DomLoc);
  // White list the internal communication protocols.
  if (DomName.equals("AF_SYSTEM") || DomName.equals("AF_LOCAL") ||
      DomName.equals("AF_UNIX") || DomName.equals("AF_RESERVED_36"))
    return State;
  State = State->addTaint(CE, C.getLocationContext());
  return State;
}

ProgramStateRef SecureCTaintChecker::postScanf(const CallExpr *CE,
                                               CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  if (CE->getNumArgs() < 2)
    return State;

  // All arguments except for the very first one should get taint.
  for (unsigned int i = 1; i < CE->getNumArgs(); ++i) {
    // The arguments are pointer arguments. The data they are pointing at is
    // tainted after the call.
    const Expr *Arg = CE->getArg(i);
    Optional<SVal> V = getPointedToSVal(C, Arg);
    if (V)
      State = State->addTaint(*V);
  }
  return State;
}

ProgramStateRef SecureCTaintChecker::postRetTaint(const CallExpr *CE,
                                                  CheckerContext &C) const {
  return C.getState()->addTaint(CE, C.getLocationContext());
}

bool SecureCTaintChecker::isStdin(const Expr *E, CheckerContext &C) {
  ProgramStateRef State = C.getState();
  SVal Val = C.getSVal(E);

  // stdin is a pointer, so it would be a region.
  const MemRegion *MemReg = Val.getAsRegion();

  // The region should be symbolic, we do not know it's value.
  const SymbolicRegion *SymReg = dyn_cast_or_null<SymbolicRegion>(MemReg);
  if (!SymReg)
    return false;

  // Get it's symbol and find the declaration region it's pointing to.
  const SymbolRegionValue *Sm =
      dyn_cast<SymbolRegionValue>(SymReg->getSymbol());
  if (!Sm)
    return false;
  const DeclRegion *DeclReg = dyn_cast_or_null<DeclRegion>(Sm->getRegion());
  if (!DeclReg)
    return false;

  // This region corresponds to a declaration, find out if it's a global/extern
  // variable named stdin with the proper type.
  if (const auto *D = dyn_cast_or_null<VarDecl>(DeclReg->getDecl())) {
    D = D->getCanonicalDecl();
    if ((D->getName().find("stdin") != StringRef::npos) && D->isExternC()) {
      const auto *PtrTy = dyn_cast<PointerType>(D->getType().getTypePtr());
      if (PtrTy && PtrTy->getPointeeType().getCanonicalType() ==
                       C.getASTContext().getFILEType().getCanonicalType())
        return true;
    }
  }
  return false;
}

static bool getPrintfFormatArgumentNum(const CallExpr *CE,
                                       const CheckerContext &C,
                                       unsigned int &ArgNum) {
  // Find if the function contains a format string argument.
  // Handles: fprintf, printf, sprintf, snprintf, vfprintf, vprintf, vsprintf,
  // vsnprintf, syslog, custom annotated functions.
  const FunctionDecl *FDecl = C.getCalleeDecl(CE);
  if (!FDecl)
    return false;
  for (const auto *Format : FDecl->specific_attrs<FormatAttr>()) {
    ArgNum = Format->getFormatIdx() - 1;
    if ((Format->getType()->getName() == "printf") && CE->getNumArgs() > ArgNum)
      return true;
  }

  // Or if a function is named setproctitle (this is a heuristic).
  if (C.getCalleeName(CE).find("setproctitle") != StringRef::npos) {
    ArgNum = 0;
    return true;
  }

  return false;
}

bool SecureCTaintChecker::generateReportIfTainted(const Expr *E,
                                                  const char Msg[],
                                                  CheckerContext &C) const {
  assert(E);

  // Check for taint.
  ProgramStateRef State = C.getState();
  Optional<SVal> PointedToSVal = getPointedToSVal(C, E);
  SVal TaintedSVal;
  if (PointedToSVal && State->isTainted(*PointedToSVal))
    TaintedSVal = *PointedToSVal;
  else if (State->isTainted(E, C.getLocationContext()))
    TaintedSVal = C.getSVal(E);
  else
	    return false;

  if (SymbolRef Sym = TaintedSVal.getAsSymbol()) {
    if (State->contains<TrustedSymbols>(Sym)) {
      std::cout << "Found sanitization \n";
      return false;
    }
  }
  // Generate diagnostic.
  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    initBugType();
    auto report = llvm::make_unique<BugReport>(*BT, Msg, N);
    report->addRange(E->getSourceRange());
    report->addVisitor(llvm::make_unique<TaintBugVisitor>(TaintedSVal));
    C.emitReport(std::move(report));
    return true;
  }
  return false;
}

bool SecureCTaintChecker::checkUncontrolledFormatString(
    const CallExpr *CE, CheckerContext &C) const {
  // Check if the function contains a format string argument.
  unsigned int ArgNum = 0;
  if (!getPrintfFormatArgumentNum(CE, C, ArgNum))
    return false;

  // If either the format string content or the pointer itself are tainted,
  // warn.
  return generateReportIfTainted(CE->getArg(ArgNum),
                                 MsgUncontrolledFormatString, C);
}

bool SecureCTaintChecker::checkSystemCall(const CallExpr *CE, StringRef Name,
                                          CheckerContext &C) const {
  // TODO: It might make sense to run this check on demand. In some cases,
  // we should check if the environment has been cleansed here. We also might
  // need to know if the user was reset before these calls(seteuid).
  unsigned ArgNum = llvm::StringSwitch<unsigned>(Name)
                        .Case("system", 0)
                        .Case("popen", 0)
                        .Case("execl", 0)
                        .Case("execle", 0)
                        .Case("execlp", 0)
                        .Case("execv", 0)
                        .Case("execvp", 0)
                        .Case("execvP", 0)
                        .Case("execve", 0)
                        .Case("dlopen", 0)
                        .Default(UINT_MAX);

  if (ArgNum == UINT_MAX || CE->getNumArgs() < (ArgNum + 1))
    return false;

  return generateReportIfTainted(CE->getArg(ArgNum), MsgSanitizeSystemArgs, C);
}

// TODO: Should this check be a part of the CString checker?
// If yes, should taint be a global setting?
bool SecureCTaintChecker::checkTaintedBufferSize(const CallExpr *CE,
                                                 const FunctionDecl *FDecl,
                                                 CheckerContext &C) const {
  // If the function has a buffer size argument, set ArgNum.
  unsigned ArgNum = InvalidArgIndex;
  unsigned BId = 0;
  if ((BId = FDecl->getMemoryFunctionKind()))
    switch (BId) {
    case Builtin::BImemcpy:
    case Builtin::BImemmove:
    case Builtin::BIstrncpy:
      ArgNum = 2;
      break;
    case Builtin::BIstrndup:
      ArgNum = 1;
      break;
    default:
      break;
    };

  if (ArgNum == InvalidArgIndex) {
    if (C.isCLibraryFunction(FDecl, "malloc") ||
        C.isCLibraryFunction(FDecl, "calloc") ||
        C.isCLibraryFunction(FDecl, "alloca"))
      ArgNum = 0;
    else if (C.isCLibraryFunction(FDecl, "memccpy"))
      ArgNum = 3;
    else if (C.isCLibraryFunction(FDecl, "realloc"))
      ArgNum = 1;
    else if (C.isCLibraryFunction(FDecl, "bcopy"))
      ArgNum = 2;
  }

  return ArgNum != InvalidArgIndex && CE->getNumArgs() > ArgNum &&
         generateReportIfTainted(CE->getArg(ArgNum), MsgTaintedBufferSize, C);
}

bool SecureCTaintChecker::checkTrustAnnotatedFunctionCall(
    const CallExpr *CE, const FunctionDecl *FDecl, CheckerContext &C) const {

  ProgramStateRef State = C.getState();
  unsigned ArgNum = InvalidArgIndex;
  for (SecureCInAttr *SCInA : FDecl->specific_attrs<SecureCInAttr>()) {
    Expr *Target = SCInA->getTarget();
    DeclRefExpr *DRE = cast<DeclRefExpr>(Target);

    if (!isa<ParmVarDecl>(DRE->getDecl())) {
      continue;
    }

    ParmVarDecl *PVD = cast<ParmVarDecl>(DRE->getDecl());
    ArgNum = PVD->getFunctionScopeIndex();

    // Process annotations
    for (Expr **APtr = SCInA->annotations_begin();
         APtr < SCInA->annotations_end(); APtr++) {
      Expr *AExpr = *APtr;
      if (isa<StringLiteral>(AExpr)) {
        StringLiteral *AL = cast<StringLiteral>(AExpr);
        if (AL->getString().equals("trusted")) {
          if (generateReportIfTainted(CE->getArg(ArgNum),
                                      MsgTaintedTrustArguments, C)) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

void ento::registerSecureCTaintChecker(CheckerManager &mgr) {
  mgr.registerChecker<SecureCTaintChecker>();
}

bool ento::shouldRegisterSecureCTaintChecker(const LangOptions &LO) {
  return true;
}