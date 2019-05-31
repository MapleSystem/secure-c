#include "SecureC.h"

#include <memory>
#include <string>

#include "clang/AST/AST.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"

#include "NullScope.h"
#include "SecureCStatistics.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

static llvm::cl::OptionCategory SecureCCategory("Secure-C Compiler");
static llvm::cl::opt<bool> DefaultNullable(
    "default-nullable",
    llvm::cl::desc("Allow unannotated pointers and default to nullable."),
    llvm::cl::cat(SecureCCategory));

enum SecureCMode { debug, trust, strict };
static llvm::cl::opt<SecureCMode> RunMode(
    "mode", llvm::cl::desc("set the mode:"),
    llvm::cl::values(clEnumVal(debug,
                               "Insert run-time checks instead of reporting "
                               "illegal access or unsafe promotion errors"),
                     clEnumVal(trust, "Trust forced promotions (default)"),
                     clEnumVal(strict, "Disallow forced promotions")),
    llvm::cl::init(trust), llvm::cl::cat(SecureCCategory));

static llvm::cl::opt<bool>
    InPlace("i", llvm::cl::desc("Inplace edit <file>s, if specified."),
            llvm::cl::cat(SecureCCategory));

static llvm::cl::opt<bool>
    CheckRedundant("check-redundant",
                   llvm::cl::desc("Report redundant null checks."),
                   llvm::cl::cat(SecureCCategory));

static llvm::cl::opt<bool>
    Statistics("dump-stats",
               llvm::cl::desc("Collect statistics about the analysis."),
               llvm::cl::cat(SecureCCategory));

static llvm::cl::opt<bool>
    SecureBuffer("secure-buffer",
                 llvm::cl::desc("Check for proper use of secure buffers."),
                 llvm::cl::init(true), llvm::cl::cat(SecureCCategory));

bool isAnnotatedNonnull(const QualType &QT) {
  if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr()))
    if (AType->getImmediateNullability() == NullabilityKind::NonNull)
      return true;
  return false;
}

static uint64_t keyFromRange(CharSourceRange &Range) {
  uint64_t RangeKey = Range.getBegin().getRawEncoding();
  RangeKey <<= 32;
  RangeKey |= Range.getEnd().getRawEncoding();
  return RangeKey;
}

SecureCVisitor::SecureCVisitor(
    ASTContext &Context,
    std::map<std::string, tooling::Replacements> &FileToReplaces)
    : Context(Context), FileToReplaces(FileToReplaces) {
  // Create an initial scope for globals
  NullScopes.push_back(llvm::make_unique<NullScope>());

  if (Statistics)
    Stats = new SecureCStatistics(this);
}

bool SecureCVisitor::shouldTraversePostOrder() { return true; }

bool SecureCVisitor::TraverseDecl(Decl *D) {
  // Don't traverse Decl in system header files
  SourceLocation Loc = D->getLocation();
  if (Loc.isValid() &&
      (Context.getSourceManager().isInSystemHeader(Loc) ||
       Context.getSourceManager().isInExternCSystemHeader(Loc))) {
    return true;
  }

  return RecursiveASTVisitor<SecureCVisitor>::TraverseDecl(D);
}

bool SecureCVisitor::VisitVarDecl(VarDecl *VD) {
  if (isa<ParmVarDecl>(VD))
    return true;

  if (VD->hasInit()) {
    const Expr *Init = VD->getInit();
    if (VD->getType()->isFunctionPointerType()) {
      VisitFuncPtrAssign(VD->getType(), Init);
    }
    if (isAnnotatedNonnull(VD->getType())) {
      if (Statistics)
        Stats->trackStatistics(Init, SecureCStatistics::cast);

      // A non-null pointer must be initialized with a non-null expression
      if (!isNonnullCompatible(Init)) {
        reportIllegalCast(VD->getType(), Init, Context);
      }
    } else {
      // Track the local nullability of this variable
      bool nonNull = isNonnullCompatible(Init);
      NullScopes.back()->setLocalNullability(VD, !nonNull);
    }
  } else if (isAnnotatedNonnull(VD->getType()) && !VD->hasExternalStorage()) {
    // Non-null variables must be initialized
    reportUninitializedNonnull(VD, Context);
  }

  return true;
}

bool SecureCVisitor::TraverseFunctionDecl(FunctionDecl *FD) {
  // Check for value-range attribute
  if (hasValueRange(FD)) {
    llvm::errs() << FD->getName() << " has a value range!!!\n";
  }

  for (unsigned int i = 0; i < FD->getNumParams(); i++) {
    const ParmVarDecl *Param = FD->getParamDecl(i);
    const QualType QT = Param->getType();
    if (dyn_cast<PointerType>(QT.getTypePtr())) {
      if (!DefaultNullable && !isNullabilityAnnotated(QT)) {
        reportUnannotatedParam(FD, Param, false, Context);
      }
    }
  }

  // Create a function scope for checked decls
  NullScopes.push_back(llvm::make_unique<NullScope>());

  RecursiveASTVisitor<SecureCVisitor>::TraverseFunctionDecl(FD);

  // Remove the function scoped checked decls
  NullScopes.pop_back();

  return true;
}

bool SecureCVisitor::TraverseIfStmt(IfStmt *If) {
  if (If->hasInitStorage()) {
    TraverseStmt(If->getInit());
  }

  if (If->hasVarStorage()) {
    TraverseStmt(If->getConditionVariableDeclStmt());
  }

  // A scope for pointers checked by the if-condition
  NullScopes.push_back(llvm::make_unique<NullScope>());

  // Analyze the condition expression for Nullability
  bool isNull = true;
  DeclRefExpr *DRE = NULL;
  if (IsNullChecker(If->getCond(), DRE, isNull)) {
    NullScopes.back()->setCheckedNullability(DRE->getDecl(), isNull);
  } else {
    TraverseStmt(If->getCond());
  }

  // Process the Then condition
  TraverseStmt(If->getThen());

  if (If->hasElseStorage()) {
    // In the else case, the values are switched
    // (decls known to be NULL in the if body are non-null in the else)
    NullScopes.back()->inverse();
    // Local null properties in the true branch don't apply to the false
    NullScopes.back()->cleanLocalNullability();

    // Process the Else condition
    TraverseStmt(If->getElse());
  }
  // TODO: handle there are both true and false branch, and one or both has
  // return.
  else if (NullScopes.back()->hasReturned()) {
    // If we return inside of an if stmt, put the inverse of the if's checked
    // decls into the function scope. For example:
    //   if (x == NULL) { return 0; }
    // After this if stmt, we are sure that x is non-null in the parent scope.
    auto &&IfScope = NullScopes[NullScopes.size() - 1];
    auto &ParentScope = NullScopes[NullScopes.size() - 2];
    // merge into the parent scope the inverse of the current scope.
    IfScope->inverse();
    ParentScope->merge(*IfScope);
  }
  NullScopes.pop_back();

  return true;
}

bool SecureCVisitor::TraverseConditionalOperator(ConditionalOperator *CO) {
  // A scope for pointers checked by the ternary operator
  NullScopes.push_back(llvm::make_unique<NullScope>());

  // Process the condition
  bool isNull = true;
  DeclRefExpr *DRE = NULL;
  if (IsNullChecker(CO->getCond(), DRE, isNull)) {
    NullScopes.back()->setCheckedNullability(DRE->getDecl(), isNull);
  } else {
    TraverseStmt(CO->getCond());
  }

  TraverseStmt(CO->getTrueExpr());

  NullScopes.back()->inverse();
  NullScopes.back()->cleanLocalNullability();

  TraverseStmt(CO->getFalseExpr());

  NullScopes.pop_back();

  return true;
}

bool SecureCVisitor::IsNullChecker(Expr *E, DeclRefExpr *&RetDRE,
                                   bool &isNull) {
  // Need to process 4 cases:
  // 1) ptr
  // 2) !ptr
  // 3) ptr == NULL
  // 4) ptr != NULL
  // 5) otherwise return false

  Expr *Stripped = E->IgnoreParenImpCasts();

  // Process 1)
  if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Stripped)) {
    // Check if it is a pointer
    bool isPtr = DRE->getType()->isPointerType();
    if (!isPtr)
      return false;
    isNull = false;
    RetDRE = DRE;
    return true;
  }
  // Process 2)
  else if (auto UO = dyn_cast<clang::UnaryOperator>(Stripped)) {
    if (UO->getOpcode() != UO_LNot)
      isNull = false;
    // Check if it is a pointer
    DeclRefExpr *DRE =
        dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts());
    if (!DRE || !DRE->getType()->isPointerType())
      return false;
    isNull = true;
    RetDRE = DRE;
    return true;
  }
  // Process 3) and 4)
  else if (auto BO = dyn_cast<clang::BinaryOperator>(Stripped)) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      // x == NULL OR x != NULL
      if (BO->getRHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *LHS =
                dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
          if (isNonnullCompatible(LHS)) {
            warnRedundantCheck(BO);
          }
          isNull = (BO->getOpcode() == BO_EQ);
          RetDRE = LHS;
          return true;
        }
      }
      // NULL == x OR NULL != x
      if (BO->getLHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *RHS =
                dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
          if (isNonnullCompatible(RHS)) {
            warnRedundantCheck(BO);
          }
          isNull = (BO->getOpcode() == BO_EQ);
          RetDRE = RHS;
          return true;
        }
      }
    }
  }
  // Process 5)
  return false;
}

bool SecureCVisitor::VisitBinaryOperator(BinaryOperator *BO) {
  // TODO: check if we are inside an if-condition, rather than e.g. "b = p
  // != NULL"
  if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
    // x == NULL OR x != NULL
    if (BO->getRHS()->isNullPointerConstant(
            Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
      if (DeclRefExpr *LHS =
              dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
        if (isNonnullCompatible(LHS)) {
          warnRedundantCheck(BO);
        }
        NullScopes.back()->setCheckedNullability(LHS->getDecl(),
                                                 BO->getOpcode() == BO_EQ);
      }
    }
    // NULL == x OR NULL != x
    if (BO->getLHS()->isNullPointerConstant(
            Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
      if (DeclRefExpr *RHS =
              dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
        if (isNonnullCompatible(RHS)) {
          warnRedundantCheck(BO);
        }
        NullScopes.back()->setCheckedNullability(RHS->getDecl(),
                                                 BO->getOpcode() == BO_EQ);
      }
    }

    return true;
  }

  // A "or" operation throws uncertainty to the checked pointers in this
  // if-condition.
  if (BO->getOpcode() == BO_LOr) {
    NullScopes.back()->setUncertain(true);
  }
  if (BO->getOpcode() == BO_LOr || BO->getOpcode() == BO_LAnd) {
    NullScopes.back()->setCompound();
  }

  if (BO->getOpcode() != BO_Assign) {
    return true;
  }

  return VisitAssign(BO->getLHS(), BO->getRHS());
}

bool SecureCVisitor::VisitAssign(Expr *LHS, Expr *RHS) {
  if (LHS->getType()->isFunctionPointerType()) {
    VisitFuncPtrAssign(LHS->getType(), RHS);
  }
  // case 1: assign nullable to a nonnull typed pointer =>
  // complain!
  if (isAnnotatedNonnull(LHS->getType())) {
    if (Statistics)
      Stats->trackStatistics(RHS, SecureCStatistics::cast);

    if (!isNonnullCompatible(RHS)) {
      reportIllegalCast(LHS->getType(), RHS, Context);
    }
  }
  // case 2: assign values to a nullable pointer =>
  // update its local status
  else if (DeclRefExpr *ref =
               dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts())) {
    bool nonNull = isNonnullCompatible(RHS);
    NullScopes.back()->setLocalNullability(ref->getDecl(), !nonNull);
  }
  return true;
}

// if LHS is a function pointer, make sure _Nonnull or _Nullable
// of the return type and parameter types match those of RHS
bool SecureCVisitor::VisitFuncPtrAssign(const QualType &Ty, const Expr *rhs) {
  auto ptype = Ty->getPointeeType();
  auto ltype = dyn_cast<FunctionType>(ptype.IgnoreParens());
  assert(ltype != NULL);
  const auto *rtype =
      dyn_cast<FunctionType>(rhs->getType()->getPointeeType().IgnoreParens());

  if (isAnnotatedNonnull(ltype->getReturnType()) &&
      !isAnnotatedNonnull(rtype->getReturnType())) {
    reportIllegalCastFuncPtr(rhs, Context);
    return true;
  }

  if (auto fptLeft = dyn_cast<FunctionProtoType>(ltype)) {
    auto fptRight = dyn_cast<FunctionProtoType>(rtype);
    assert(fptRight);
    auto lParams = fptLeft->getParamTypes();
    auto rParams = fptRight->getParamTypes();
    assert(lParams.size() == rParams.size());
    for (size_t i = 0; i < lParams.size(); i++) {
      if (!isAnnotatedNonnull(lParams[i]) && isAnnotatedNonnull(rParams[i])) {
        reportIllegalCastFuncPtr(rhs, Context);
        return true;
      }
    }
  }
  return true;
}

bool SecureCVisitor::VisitCallExpr(CallExpr *CE) {
  Expr *Callee = CE->getCallee()->IgnoreParenImpCasts();

  // If the callee is a function pointer, it should be non-null
  if (Callee->isLValue()) {
    if (Statistics)
      Stats->trackStatistics(Callee, SecureCStatistics::call);

    if (!isNonnullCompatible(Callee)) {
      reportIllegalAccess(Callee, CE, Context);
    }
  }

  const FunctionProtoType *FTy =
      dyn_cast<FunctionProtoType>(Callee->getType().getTypePtr());
  if (FTy == nullptr)
    return true;

  for (unsigned int i = 0; i < FTy->getNumParams(); i++) {
    const QualType QT = FTy->getParamType(i);
    if (isAnnotatedNonnull(QT)) {
      const Expr *Arg = CE->getArg(i);

      if (Statistics)
        Stats->trackStatistics(Arg, SecureCStatistics::cast);

      if (!isNonnullCompatible(Arg)) {
        reportIllegalCast(QT, Arg, Context);
      }
    }
  }

  for (auto *SB : CE->getCalleeDecl()->specific_attrs<SecureBufferAttr>()) {
    Expr *Buffer = SB->getBuffer();
    Expr *Length = SB->getLength();

    // Get the buffer and length index
    DeclRefExpr *DRE = cast<DeclRefExpr>(Buffer);
    ParmVarDecl *PVD = cast<ParmVarDecl>(DRE->getDecl());
    unsigned BI = PVD->getFunctionScopeIndex();
    // Check if the length is DeclRefExpr and ParmVarDecl
    if (!isa<DeclRefExpr>(Length)) {
      return true;
    }
    DRE = cast<DeclRefExpr>(Length);
    if (!isa<ParmVarDecl>(DRE->getDecl())) {
      return true;
    }
    PVD = cast<ParmVarDecl>(DRE->getDecl());
    unsigned LI = PVD->getFunctionScopeIndex();

    Expr *BArg = CE->getArg(BI); // Buffer argument
    Expr *LArg = CE->getArg(LI); // Length argument
    Expr *Eval = nullptr;        // Expression to be evaluated
    Expr *BLE = nullptr;         // Buffer length expression

    if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(BArg->IgnoreParenImpCasts())) {
      QualType ArgTy = DRE->getDecl()->getType();
      QualType LTy;
      // Buffer can be a static, variable length, or dynamic array
      if (ArgTy->isArrayType()) {
        LTy = cast<ArrayType>(ArgTy)->getElementType();
        if (const ConstantArrayType *CAT =
                Context.getAsConstantArrayType(ArgTy)) {
          unsigned Size = static_cast<unsigned>(Context.getTypeSize(LTy));
          BLE = IntegerLiteral::Create(
              Context, llvm::APInt(Size, CAT->getSize().getSExtValue()), LTy,
              SourceLocation());
        } else if (const VariableArrayType *VAT =
                       Context.getAsVariableArrayType(ArgTy)) {
          BLE = VAT->getSizeExpr();
        }
      } else if (ArgTy->isPointerType()) {
        LTy = cast<PointerType>(ArgTy)->getPointeeType();
        unsigned Size = static_cast<unsigned>(Context.getTypeSize(LTy));
        IdentifierInfo *II_malloc = &Context.Idents.get(
            "malloc"); // TODO: need a better way to handle this
        // Extract the malloc argument expression
        if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          if (Expr *Init = VD->getInit()) {
            if (CStyleCastExpr *CSCE = dyn_cast<CStyleCastExpr>(Init)) {
              if (CallExpr *ICE = dyn_cast<CallExpr>(CSCE->getSubExpr())) {
                if (FunctionDecl *FD = ICE->getDirectCallee()) {
                  IdentifierInfo *II = FD->getIdentifier();
                  if (II == II_malloc) {
                    Expr *MArg = ICE->getArg(0); // Malloc argument expression
                    Expr::EvalResult MSize;
                    if (!MArg->EvaluateAsInt(MSize, Context)) {
                      return false;
                    }
                    unsigned PEleSize = Size / 8; // Pointer element size
                    unsigned NEleForMalloc =
                        MSize.Val.getInt().getExtValue() /
                        PEleSize; // Number of elements for malloc
                    BLE = IntegerLiteral::Create(
                        Context, llvm::APInt(Size, NEleForMalloc), LTy,
                        SourceLocation());
                  } else {
                    // Find out if the callee has secure buffer attribute
                    // Extract the length expression
                  }
                }
              }
            }
          }
        }
      }
      Eval = new (Context)
          BinaryOperator(LArg, BLE, BO_LE, LTy, VK_RValue, OK_Ordinary,
                         SourceLocation(), FPOptions());
      bool Result;
      if (Eval->EvaluateAsBooleanCondition(Result, Context)) {
        if (!Result) {
          reportSecureBufferInvalidLength(LArg, BArg, BLE);
        }
      } else {
        reportSecureBufferUndeterminedLength(LArg, BArg);
      }
    }
  }
  return true;
}

bool SecureCVisitor::VisitMemberExpr(MemberExpr *ME) {
  Expr *Base = ME->getBase();
  if (ME->isArrow()) {
    if (Statistics)
      Stats->trackStatistics(Base, SecureCStatistics::member);

    if (!isNonnullCompatible(Base)) {
      reportIllegalAccess(Base, ME, Context);
    }
  }

  return true;
}

bool SecureCVisitor::VisitArraySubscriptExpr(ArraySubscriptExpr *AE) {
  Expr *Base = AE->getBase();
  if (Statistics)
    Stats->trackStatistics(Base, SecureCStatistics::subscript);

  if (!isNonnullCompatible(Base))
    reportIllegalAccess(Base, AE, Context);

  // Check secure buffer requirements
  Expr *Stripped = Base->IgnoreParenCasts();
  if (SecureBuffer && Stripped->getType()->isPointerType()) {
    if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base->IgnoreParenImpCasts())) {
      if (SecureBufferAttr *SB = DRE->getDecl()->getAttr<SecureBufferAttr>()) {
        Expr *MinCond = nullptr;
        Expr *MaxCond = nullptr;
        bool OutOfRange = false;

        QualType IdxTy = AE->getIdx()->getType();

        // Verify that the index is unsigned or >= 0
        if (IdxTy->isSignedIntegerType()) {
          unsigned Size = static_cast<unsigned>(Context.getTypeSize(IdxTy));
          Expr *Zero = IntegerLiteral::Create(Context, llvm::APInt(Size, 0),
                                              IdxTy, SourceLocation());
          MinCond = new (Context)
              BinaryOperator(AE->getIdx(), Zero, BO_GE, IdxTy, VK_RValue,
                             OK_Ordinary, SourceLocation(), FPOptions());
          bool Result;
          // TODO: Evaluate using value ranges from attributes and analysis
          if (MinCond->EvaluateAsBooleanCondition(Result, Context)) {
            // delete MinCond;
            MinCond = nullptr;
            if (!Result) {
              OutOfRange = true;
              reportSecureBufferOutOfRange(AE, AE->getIdx());
            }
          }
        }

        // Verify that the index is less than the length
        Expr *Max = SB->getLength();
        if (Max->getType() != IdxTy) {
          Max = ImplicitCastExpr::Create(Context, IdxTy, CK_IntegralCast, Max,
                                         nullptr, VK_RValue);
        }
        MaxCond = new (Context)
            BinaryOperator(AE->getIdx(), Max, BO_LT, IdxTy, VK_RValue,
                           OK_Ordinary, SourceLocation(), FPOptions());
        bool Result;
        // TODO: Evaluate using value ranges from attributes and analysis
        if (MaxCond->EvaluateAsBooleanCondition(Result, Context)) {
          // delete MaxCond;
          MaxCond = nullptr;
          if (!Result) {
            OutOfRange = true;
            reportSecureBufferOutOfRange(AE, AE->getIdx());
          }
        }

        if (!OutOfRange && (MinCond || MaxCond)) {
          Expr *Cond;
          if (MinCond && MaxCond) {
            Cond = new (Context) BinaryOperator(
                MinCond, MaxCond, BO_LAnd, Context.BoolTy, VK_RValue,
                OK_Ordinary, SourceLocation(), FPOptions());
          } else if (MinCond) {
            Cond = MinCond;
          } else {
            Cond = MaxCond;
          }

          reportUncheckedSecureBuffer(AE, AE->getIdx(), SB->getLength(), Cond);
        }
      } else {
        reportMissingSecureBuffer(Base, AE);
      }
    }
    // TODO: Handle other bases (member accesses, dereferences, etc.)
  }

  return true;
}

bool SecureCVisitor::VisitUnaryOperator(UnaryOperator *UO) {
  if (UO->getOpcode() != UO_Deref)
    return true;

  auto expr = UO->getSubExpr()->IgnoreParenImpCasts();

  if (Statistics)
    Stats->trackStatistics(expr, SecureCStatistics::deref);

  if (!isNonnullCompatible(expr)) {
    reportIllegalAccess(expr, UO, Context);
  }

  return true;
}

bool SecureCVisitor::VisitReturnStmt(ReturnStmt *RS) {
  NullScopes.back()->setReturned();
  return true;
}

bool SecureCVisitor::isDeterminedNonNull(const Expr *E) {
  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)) {
    Decl const *D = DRE->getDecl();
    // Early return if we are certain the pointer is null or non-null
    for (int i = NullScopes.size() - 1; i >= 0; i--) {
      if (NullScopes[i]->isNull(D))
        return false;
      else if (NullScopes[i]->isNotNull(D))
        return true;
    }
  }

  return false;
}

void SecureCVisitor::reportStatistics(bool DebugMode) {
  if (Statistics)
    Stats->reportStatistics(DebugMode);
}

void SecureCVisitor::insertRuntimeNullCheck(const Expr *Pointer) {
  // Don't insert run-time checks into system macros
  if (Context.getSourceManager().isInSystemMacro(Pointer->getBeginLoc()))
    return;

  QualType Ty = Pointer->getType();

  // If the type is already annotated, strip the annotation
  if (isNullabilityAnnotated(Ty)) {
    AttributedType::stripOuterNullability(Ty);
  }
  QualType modifiedTy = Ty;
  Ty = Context.getAttributedType(attr::TypeNonNull, modifiedTy, modifiedTy);
  std::string TyString = Ty.getAsString();

  CharSourceRange Range;
  StringRef PtrExpr = getSourceString(Pointer, Range);

  std::string ReplacementText =
      "((" + TyString +
      ")(_CheckNonNull(__FILE__, __LINE__, __extension__ "
      "__PRETTY_FUNCTION__, " +
      PtrExpr.str() + ")))";

  // Avoid duplicate run-time checks
  if (InsertedChecks.find(keyFromRange(Range)) != InsertedChecks.end()) {
    if (Statistics)
      Stats->duplicateCheck();
    return;
  }

  if (Statistics)
    Stats->insertCheck();
  InsertedChecks[keyFromRange(Range)] = true;

  Replacement Rep(Context.getSourceManager(), Range, ReplacementText);

  // Include the Secure-C header once in each modified file
  if (FileToReplaces[Rep.getFilePath()].empty()) {
    Replacement Header(Rep.getFilePath(), 0, 0, "#include <secure_c.h>\n");
    llvm::Error Err = FileToReplaces[Rep.getFilePath()].add(Header);
    llvm::handleAllErrors(std::move(Err), [&](const ReplacementError &RE) {
      reportFailedHeaderInsert(RE.message());
    });
  }

  llvm::Error Err = FileToReplaces[Rep.getFilePath()].add(Rep);
  if (Err) {
    llvm::Error RepErr =
        handleReplacementError(std::move(Err), PtrExpr.str(), TyString);
    llvm::handleAllErrors(std::move(RepErr), [&](const ReplacementError &RE) {
      reportFailedReplacement(Pointer, RE.message());
    });
  }
}

void SecureCVisitor::insertRuntimeRangeCheck(const Expr *Val,
                                             const Expr *Cond) {
  // TODO: Insert range check
}

StringRef SecureCVisitor::getSourceString(const Expr *Pointer,
                                          CharSourceRange &Range) {
  Range = CharSourceRange::getTokenRange(Pointer->getSourceRange());
  SourceLocation Begin = Pointer->getBeginLoc();
  SourceLocation End = Pointer->getEndLoc();

  // If this pointer is actually a macro expansion, get the macro location
  if (Context.getSourceManager().isMacroArgExpansion(Begin, &Begin) ||
      Context.getSourceManager().isMacroBodyExpansion(Begin)) {
    // If the end of this expresion is also in the macro arg expansion,
    // then this replacement is purely within the arg, so it should go
    // at the expansion site, not in the macro.
    if (Context.getSourceManager().isMacroArgExpansion(End)) {
      Begin = Pointer->getBeginLoc();
    }

    Begin = Context.getSourceManager().getSpellingLoc(Begin);
    End = Context.getSourceManager().getSpellingLoc(End);

    End = Lexer::getLocForEndOfToken(End, 0, Context.getSourceManager(),
                                     Context.getLangOpts());

    Range = CharSourceRange::getCharRange(Begin, End);
  }

  return Lexer::getSourceText(Range, Context.getSourceManager(),
                              Context.getLangOpts());
}

bool SecureCVisitor::isDuplicateReplacement(Replacement &Old,
                                            Replacement &New) {
  return New.getOffset() >= Old.getOffset() &&
         (New.getOffset() + New.getLength()) <=
             (Old.getOffset() + Old.getLength()) &&
         Old.getReplacementText().find(New.getReplacementText()) !=
             std::string::npos;
}

bool SecureCVisitor::isExistingReplacementInside(Replacement &Old,
                                                 Replacement &New) {
  return New.getOffset() <= Old.getOffset() &&
         (New.getOffset() + New.getLength()) >=
             (Old.getOffset() + Old.getLength());
}

llvm::Error SecureCVisitor::handleReplacementError(llvm::Error Err,
                                                   std::string PtrExpr,
                                                   std::string TyString) {
  return llvm::handleErrors(
      std::move(Err), [&](const ReplacementError &RE) -> llvm::Error {
        if (RE.get() != replacement_error::overlap_conflict) {
          return llvm::make_error<ReplacementError>(RE);
        }

        Replacement Old = RE.getExistingReplacement().getValue();
        Replacement New = RE.getNewReplacement().getValue();

        // This fix works if there is an overlap conflict and the old
        // replacement is within the new replacement.
        if (isExistingReplacementInside(Old, New)) {
          unsigned NewLength = New.getLength() - Old.getLength() +
                               Old.getReplacementText().size();
          unsigned NewOffset =
              FileToReplaces[New.getFilePath()].getShiftedCodePosition(
                  New.getOffset());
          unsigned InternalOffset = Old.getOffset() - New.getOffset();
          std::string ExtendedExpr =
              PtrExpr.substr(0, InternalOffset) +
              Old.getReplacementText().str() +
              PtrExpr.substr(InternalOffset + Old.getLength());
          std::string ReplacementText =
              "((" + TyString +
              ")(_CheckNonNull(__FILE__, __LINE__, __extension__ "
              "__PRETTY_FUNCTION__, " +
              ExtendedExpr + ")))";
          Replacement NewR(New.getFilePath(), NewOffset, NewLength,
                           ReplacementText);
          FileToReplaces[New.getFilePath()] =
              FileToReplaces[New.getFilePath()].merge(Replacements(NewR));
          return llvm::Error::success();
        }

        return llvm::make_error<ReplacementError>(RE);
      });
}

void SecureCVisitor::reportIllegalCast(const QualType &Ty, const Expr *Pointer,
                                       const ASTContext &Context) {
  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                               "unsafe promotion from nullable pointer type "
                               "'%0' to non-nullable pointer type '%1'");

  // In debug mode, we insert a run-time check into the code
  if (RunMode == debug) {
    insertRuntimeNullCheck(Pointer);
    ID = DE.getCustomDiagID(
        clang::DiagnosticsEngine::Remark,
        "unsafe non-null promotion, inserting run-time check");
  }

  auto DB = DE.Report(Pointer->getBeginLoc(), ID);
  DB.AddString(Pointer->IgnoreParenImpCasts()->getType().getAsString());
  DB.AddString(Ty.getAsString());

  const auto Range =
      clang::CharSourceRange::getCharRange(Pointer->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportIllegalAccess(const Expr *Pointer,
                                         const Expr *Access,
                                         const ASTContext &Context) {
  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                               "illegal access of nullable pointer type '%0'");

  // In debug mode, we insert a run-time check into the code
  if (RunMode == debug) {
    insertRuntimeNullCheck(Pointer);
    ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Remark,
                            "illegal access of nullable pointer type, "
                            "inserting run-time check");
  }

  auto DB = DE.Report(Access->getBeginLoc(), ID);
  DB.AddString(Pointer->getType().getAsString());

  const auto Range =
      clang::CharSourceRange::getCharRange(Access->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportUnannotatedParam(const FunctionDecl *FD,
                                            const ParmVarDecl *Param,
                                            bool suggestNonnull,
                                            const ASTContext &Context) {
  auto &DE = Context.getDiagnostics();
  const auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                     "pointer parameter is not annotated "
                                     "with either '_Nonnull' or '_Nullable'");

  auto DB = DE.Report(Param->getTypeSpecStartLoc(), ID);
  const auto Range =
      clang::CharSourceRange::getCharRange(Param->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportUninitializedNonnull(const VarDecl *VD,
                                                const ASTContext &Context) {
  auto &DE = Context.getDiagnostics();
  const auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                     "Nonnull pointer is not initialized");

  auto DB = DE.Report(VD->getTypeSpecStartLoc(), ID);
  const auto Range = clang::CharSourceRange::getCharRange(VD->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportIllegalCastFuncPtr(const Expr *rhs,
                                              const ASTContext &Context) {
  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(
      clang::DiagnosticsEngine::Error,
      "unsafe nullability mismatch in function pointer assignment '%0'");

  auto DB = DE.Report(rhs->getBeginLoc(), ID);
  DB.AddString(rhs->IgnoreParenImpCasts()->getType().getAsString());

  const auto Range =
      clang::CharSourceRange::getCharRange(rhs->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::warnRedundantCheck(const Expr *Check) {
  if (Statistics)
    Stats->redundantCheck();

  if (!CheckRedundant)
    return;

  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Warning,
                               "possibly redundant null-check");

  auto DB = DE.Report(Check->getExprLoc(), ID);

  const auto Range =
      clang::CharSourceRange::getCharRange(Check->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportFailedReplacement(const Expr *Pointer,
                                             std::string ErrMsg) {
  auto &DE = Context.getDiagnostics();
  const auto ID =
      DE.getCustomDiagID(clang::DiagnosticsEngine::Fatal,
                         "Failed to insert run-time check: %0\n"
                         "Please report this error to the Secure-C team.\n");

  auto DB = DE.Report(Pointer->getExprLoc(), ID);
  const auto Range =
      clang::CharSourceRange::getCharRange(Pointer->getSourceRange());
  DB.AddSourceRange(Range);
  DB.AddString(ErrMsg);
}

void SecureCVisitor::reportFailedHeaderInsert(std::string ErrMsg) {
  auto &DE = Context.getDiagnostics();
  const auto ID =
      DE.getCustomDiagID(clang::DiagnosticsEngine::Fatal,
                         "Failed to insert Secure-C header: %0\n"
                         "Please report this error to the Secure-C team.\n");

  auto DB = DE.Report(ID);
  DB.AddString(ErrMsg);
}

void SecureCVisitor::reportMissingSecureBuffer(const Expr *Pointer,
                                               const Expr *Access) {
  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(
      clang::DiagnosticsEngine::Error,
      "illegal access of pointer without secure_buffer attribute");

  auto DB = DE.Report(Access->getBeginLoc(), ID);
  DB.AddString(Pointer->getType().getAsString());

  const auto Range =
      clang::CharSourceRange::getCharRange(Access->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportUncheckedSecureBuffer(const Expr *Access,
                                                 const Expr *Index,
                                                 const Expr *Length,
                                                 const Expr *Cond) {
  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(
      clang::DiagnosticsEngine::Error,
      "unable to guarantee that index is within range of secure buffer");

  // In debug mode, we insert a run-time check into the code
  if (RunMode == debug) {
    insertRuntimeRangeCheck(Index, Cond);
    ID = DE.getCustomDiagID(
        clang::DiagnosticsEngine::Remark,
        "unable to guarantee that index is within range of secure buffer,"
        " inserting run-time check");
  }

  auto DB = DE.Report(Index->getBeginLoc(), ID);

  const auto Range =
      clang::CharSourceRange::getCharRange(Access->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportSecureBufferOutOfRange(const Expr *Access,
                                                  const Expr *Index) {
  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                               "index out of range for secure buffer");

  auto DB = DE.Report(Index->getBeginLoc(), ID);

  const auto Range =
      clang::CharSourceRange::getCharRange(Access->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportSecureBufferInvalidLength(const Expr *LExpr,
                                                     const Expr *BExpr,
                                                     const Expr *BLExpr) {
  auto &DE = Context.getDiagnostics();
  auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                               "%0 is an invalid length for %1 (length %2)");

  auto DB = DE.Report(LExpr->getBeginLoc(), ID);
  Expr::EvalResult Size;
  LExpr->EvaluateAsInt(Size, Context);
  DB.AddString(std::to_string(Size.Val.getInt().getExtValue()));
  const DeclRefExpr *DRE = cast<DeclRefExpr>(BExpr->IgnoreParenImpCasts());
  DB.AddString(DRE->getNameInfo().getAsString());
  BLExpr->EvaluateAsInt(Size, Context);
  DB.AddString(std::to_string(Size.Val.getInt().getExtValue()));

  const auto Range =
      clang::CharSourceRange::getCharRange(LExpr->getSourceRange());
  DB.AddSourceRange(Range);
}

void SecureCVisitor::reportSecureBufferUndeterminedLength(const Expr *LExpr,
                                                          const Expr *BExpr) {
  auto &DE = Context.getDiagnostics();
  auto ID =
      DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                         "%0 is not guaranteed to be a valid length for %1");

  auto DB = DE.Report(LExpr->getBeginLoc(), ID);
  auto Range = clang::CharSourceRange::getCharRange(LExpr->getSourceRange());
  DB.AddString(getSourceString(LExpr, Range));
  const DeclRefExpr *DRE = cast<DeclRefExpr>(BExpr->IgnoreParenImpCasts());
  DB.AddString(DRE->getNameInfo().getAsString());

  DB.AddSourceRange(Range);
}

bool SecureCVisitor::isNullabilityAnnotated(const QualType &QT) {
  if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr()))
    if (AType->getImmediateNullability() != None)
      return true;
  return false;
}

bool SecureCVisitor::hasValueRange(const FunctionDecl *FD) {
  return FD->hasAttr<ValueRangeAttr>();
}

bool SecureCVisitor::isNonnullCompatible(Expr const *E) {
  // Strip off
  Expr const *Stripped = E->IgnoreParenImpCasts();

  // We can ignore casts that do not involve nullability
  while (const CastExpr *CE = dyn_cast<CastExpr>(Stripped)) {
    if (isNullabilityAnnotated(Stripped->getType()))
      break;
    Stripped = CE->getSubExpr()->IgnoreParenImpCasts();
  }

  // Is the expr attributed with nonnull?
  if (isAnnotatedNonnull(Stripped->getType()))
    return true;

  // Is the expr taking an address of an object?
  if (auto UO = dyn_cast<clang::UnaryOperator>(Stripped))
    if (UO->getOpcode() == UO_AddrOf)
      return true;

  // Is the expr a constant array, e.g. a literal string?
  if (isa<ConstantArrayType>(Stripped->getType()))
    return true;

  // Is the expr a function?
  if (isa<FunctionType>(Stripped->getType()))
    return true;

  // Is the expr referring to a known non-null decl?
  if (isDeterminedNonNull(Stripped))
    return true;

  return false;
}

class SecureCConsumer : public clang::ASTConsumer {
public:
  explicit SecureCConsumer(

      std::map<std::string, tooling::Replacements> &FileToReplaces)
      : FileToReplaces(FileToReplaces) {}

  virtual void HandleTranslationUnit(clang::ASTContext &Context) {
    SecureCVisitor Visitor(Context, FileToReplaces);
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    if (Statistics)
      Visitor.reportStatistics(RunMode == debug);
  }

private:
  std::map<std::string, tooling::Replacements> &FileToReplaces;
};

struct SecureCConsumerFactory {
  SecureCConsumerFactory(
      std::map<std::string, tooling::Replacements> &FileToReplaces)
      : FileToReplaces(FileToReplaces){};
  std::unique_ptr<ASTConsumer> newASTConsumer() {
    std::unique_ptr<ASTConsumer> Consumer(new SecureCConsumer(FileToReplaces));
    return Consumer;
  }
  std::map<std::string, tooling::Replacements> &FileToReplaces;
};

int main(int argc, const char **argv) {
  CommonOptionsParser op(argc, argv, SecureCCategory);
  RefactoringTool Tool(op.getCompilations(), op.getSourcePathList());

  SecureCConsumerFactory ConsumerFactory(Tool.getReplacements());

  if (InPlace) {
    return Tool.runAndSave(newFrontendActionFactory(&ConsumerFactory).get());
  }

  if (int Result = Tool.run(newFrontendActionFactory(&ConsumerFactory).get())) {
    return Result;
  }

  IntrusiveRefCntPtr<DiagnosticOptions> DiagOpts = new DiagnosticOptions();
  DiagnosticsEngine Diagnostics(
      IntrusiveRefCntPtr<DiagnosticIDs>(new DiagnosticIDs()), &*DiagOpts,
      new TextDiagnosticPrinter(llvm::errs(), &*DiagOpts), true);
  SourceManager Sources(Diagnostics, Tool.getFiles());

  // Apply all replacements to a rewriter.
  Rewriter Rewrite(Sources, LangOptions());
  Tool.applyAllReplacements(Rewrite);

  // Query the rewriter for all the files it has rewritten, dumping their
  // new contents to stdout.
  for (Rewriter::buffer_iterator I = Rewrite.buffer_begin(),
                                 E = Rewrite.buffer_end();
       I != E; ++I) {
    const FileEntry *Entry = Sources.getFileEntryForID(I->first);
    llvm::outs() << "Rewrite buffer for file: " << Entry->getName() << "\n";
    I->second.write(llvm::outs());
  }

  return 0;
}
