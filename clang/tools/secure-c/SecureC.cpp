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

bool isAnnotatedNonnull(const QualType &QT) {
  if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr()))
    if (AType->getImmediateNullability() == NullabilityKind::NonNull)
      return true;
  return false;
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

  TraverseStmt(If->getCond());
  TraverseStmt(If->getThen());

  if (If->hasElseStorage()) {
    // In the else case, the values are switched
    // (decls known to be NULL in the if body are non-null in the else)
    NullScopes.back()->inverse();
    // Local null properties in the true branch don't apply to the false
    NullScopes.back()->cleanLocalNullability();
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

void SecureCVisitor::insertRuntimeCheck(const Expr *Pointer) {
  if (Context.getSourceManager().isInSystemMacro(Pointer->getBeginLoc()))
    return;

  if (Statistics)
    Stats->insertCheck();

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

        // Check for the case of a macro replacement that has already
        // been completed
        if (isDuplicateReplacement(Old, New)) {
          if (Statistics)
            Stats->duplicateCheck();
          return llvm::Error::success();
        }

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
    insertRuntimeCheck(Pointer);
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
    insertRuntimeCheck(Pointer);
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

bool SecureCVisitor::isNullabilityAnnotated(const QualType &QT) {
  if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr()))
    if (AType->getImmediateNullability() != None)
      return true;
  return false;
}

bool SecureCVisitor::isNonnullCompatible(Expr const *E) {
  // Strip off
  Expr const *Stripped = E->IgnoreParenImpCasts();

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
