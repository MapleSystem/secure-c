#include <string>

#include "clang/AST/AST.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
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

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::driver;
using namespace clang::tooling;

static llvm::cl::OptionCategory
    SecurifyCategory("Secure-C Annotation Insertion Tool");
static llvm::cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static llvm::cl::opt<bool>
    InPlace("i", llvm::cl::desc("Inplace edit <file>s, if specified."),
            llvm::cl::cat(SecurifyCategory));
static llvm::cl::opt<bool>
    ParamsOnly("params-only",
               llvm::cl::desc("Only annotate function parameters."),
               llvm::cl::cat(SecurifyCategory));
static llvm::cl::opt<bool> DefaultNonNull(
    "default-nonnull",
    llvm::cl::desc(
        "When nullability cannot be determined, default to non-null."),
    llvm::cl::cat(SecurifyCategory));
static llvm::cl::opt<bool>
    DefaultNullable("default-nullable",
                    llvm::cl::desc("When nullability cannot be determined, "
                                   "default to nullable (default)."),
                    llvm::cl::cat(SecurifyCategory));

class SecurifyVisitor : public RecursiveASTVisitor<SecurifyVisitor> {
public:
  explicit SecurifyVisitor(
      ASTContext &Context,
      std::map<std::string, tooling::Replacements> &FileToReplaces)
      : Context(Context), FileToReplaces(FileToReplaces) {}

  void SecurifyDecl(Decl *D) {
    TraverseDecl(D);
    createVarDeclReplacements();
  }

  bool TraverseDecl(Decl *D) {
    // Don't traverse in system header files
    SourceLocation Loc = D->getLocation();
    if (Loc.isValid() &&
        (Context.getSourceManager().isInSystemHeader(Loc) ||
         Context.getSourceManager().isInExternCSystemHeader(Loc))) {
      return true;
    }

    RecursiveASTVisitor<SecurifyVisitor>::TraverseDecl(D);
    return true;
  }

  bool TraverseFunctionDecl(FunctionDecl *FD) {
    // If this function has already been analyzed, skip it
    if (FuncsAnalyzed.find(FD) != FuncsAnalyzed.end()) {
      return true;
    }

    FunctionDecl *Definition = FD;

    // If this is a declaration (with no body), save it to be updated after
    // processing the definition
    if (!FD->doesThisDeclarationHaveABody()) {
      if (FD->hasBody()) {
        Definition = FD->getDefinition();
      } else {
        // There is no definition for this function
        return true;
      }
    }

    if (FuncsAnalyzed.find(Definition) == FuncsAnalyzed.end()) {
      RecursiveASTVisitor<SecurifyVisitor>::TraverseFunctionDecl(Definition);

      // Parameters that were not annotated should be marked with default
      for (unsigned int i = 0; i < Definition->getNumParams(); i++) {
        const ParmVarDecl *Param = Definition->getParamDecl(i);
        if (isCandidate(Param)) {
          auto D = PtrVars.find(Param);
          if (D == PtrVars.end()) {
            if (DefaultNonNull) {
              makeNonNull(Param);
            } else {
              makeNullable(Param);
            }
          }
        }
      }

      if (isCandidate(Definition->getReturnType())) {
        createReturnValueReplacement(Definition,
                                     ReturnsNonNull.getValueOr(DefaultNonNull));
      }

      FuncsAnalyzed.insert(Definition);
    }

    // If this was a declaration, update its parameters
    if (Definition != FD) {
      for (unsigned int i = 0; i < Definition->getNumParams(); i++) {
        const ParmVarDecl *DeclParam = FD->getParamDecl(i);
        const ParmVarDecl *Param = Definition->getParamDecl(i);
        if (isNonNull(Param)) {
          makeNonNull(DeclParam);
        } else {
          makeNullable(DeclParam);
        }
      }

      if (isCandidate(FD->getReturnType())) {
        createReturnValueReplacement(FD,
                                     ReturnsNonNull.getValueOr(DefaultNonNull));
      }

      FuncsAnalyzed.insert(FD);
    }

    ReturnsNonNull.reset();

    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      // x == NULL OR x != NULL
      if (BO->getRHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *LHS =
                dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
          // If this is a null-check inside an assert, assume non-null
          if (TraversingAssert && BO->getOpcode() == BO_NE) {
            makeNonNull(LHS);
          } else {
            // else, assume nullable
            makeNullable(LHS);
          }
        }
      }
      // NULL == x OR NULL != x
      if (BO->getLHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *RHS =
                dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
          // If this is a null-check inside an assert, assume non-null
          if (TraversingAssert && BO->getOpcode() == BO_NE) {
            makeNonNull(RHS);
          } else {
            // else, assume nullable
            makeNullable(RHS);
          }
        }
      }

      return true;
    }

    if (BO->getOpcode() == BO_Assign) {
      // Assignment to a non-null (assume non-null)
      if (isNonNull(BO->getLHS())) {
        if (DeclRefExpr *RHS =
                dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
          makeNonNull(RHS);
        }
      }

      // Assigning NULL to a pointer (assume nullable)
      if (BO->getRHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *LHS =
                dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
          makeNullable(LHS);
        }
      }
    }

    return true;
  }

  bool TraverseCallExpr(CallExpr *CE) {
    // Check for assertions of non-null pointers
    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD != NULL && FD->getName() == "assert") {
      TraversingAssert = true;
      for (auto arg : CE->arguments()) {
        TraverseStmt(arg);
      }
      TraversingAssert = false;
      return true;
    }

    return RecursiveASTVisitor<SecurifyVisitor>::TraverseCallExpr(CE);
  }

  bool VisitCallExpr(CallExpr *CE) {
    const DeclRefExpr *DRE =
        dyn_cast<DeclRefExpr>(CE->getCallee()->IgnoreParenImpCasts());
    if (!DRE)
      return true;

    // If the callee is a variable (function pointer), it should be non-null
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      makeNonNull(VD);
      return true;
    }

    if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
      if (!FD->doesThisDeclarationHaveABody()) {
        // If FD is a declaration without a body, get the definition
        if (FD->hasBody()) {
          FD = FD->getDefinition();
        } else if (isUnannotated(FD)) {
          // If there is no body, and it is not annotated, emit a warning
          auto &DE = Context.getDiagnostics();
          const auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Warning,
                                             "calling unannotated function");

          auto DB = DE.Report(CE->getBeginLoc(), ID);
          const auto Range =
              clang::CharSourceRange::getCharRange(CE->getSourceRange());
          DB.AddSourceRange(Range);
        }
      }

      for (unsigned int i = 0; i < FD->getNumParams(); i++) {
        const ParmVarDecl *Param = FD->getParamDecl(i);
        // Check for non-null parameters
        if (isNonNull(Param)) {
          if (DeclRefExpr *DRE =
                  dyn_cast<DeclRefExpr>(CE->getArg(i)->IgnoreParenImpCasts())) {
            makeNonNull(DRE);
          }
        }
      }
    }
    return true;
  }

  bool VisitMemberExpr(MemberExpr *ME) {
    if (DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(ME->getBase()->IgnoreParenImpCasts())) {
      makeNonNull(DRE);
    }

    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->getOpcode() != UO_Deref) {
      return true;
    }
    if (DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts())) {
      makeNonNull(DRE);
    }

    return true;
  }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    if (DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(ASE->getBase()->IgnoreParenImpCasts())) {
      makeNonNull(DRE);
    }

    return true;
  }

  bool VisitDeclStmt(DeclStmt *DS) {
    for (auto DI = DS->decl_begin(); DI != DS->decl_end(); ++DI) {
      if (VarDecl *VD = dyn_cast<VarDecl>(*DI)) {
        // If it is not a pointer, or it is already annotated, skip it
        if (!isCandidate(VD)) {
          continue;
        }

        // An uninitialized pointer must be nullable
        if (!VD->hasInit()) {
          makeNullable(VD);
        } else {
          // A pointer initialized with NULL must be nullable
          if (VD->getInit()->isNullPointerConstant(
                  Context, Expr::NPC_NeverValueDependent) !=
              Expr::NPCK_NotNull) {
            makeNullable(VD);
          }
          // Any other initializer that is not non-null compatible means that
          // the pointer must be nullable
          else if (!isNonNullCompatible(VD->getInit())) {
            makeNullable(VD);
          }
        }
      }
    }

    return true;
  }

  bool VisitReturnStmt(ReturnStmt *RS) {
    if (Expr *RE = RS->getRetValue()) {
      ReturnsNonNull =
          ReturnsNonNull.getValueOr(true) && isNonNullCompatible(RE);
    }

    return true;
  }

private:
  ASTContext &Context;

  // Functions that have been analyzed
  std::set<const FunctionDecl *> FuncsAnalyzed =
      std::set<const FunctionDecl *>();

  // Pointers that have been identified
  std::map<const VarDecl *, NullabilityKind> PtrVars =
      std::map<const VarDecl *, NullabilityKind>();

  // Track the nullability of a function's return value <valid, non-null>
  Optional<bool> ReturnsNonNull;

  // True when traversing inside an assert statement
  bool TraversingAssert = false;

  std::map<std::string, tooling::Replacements> &FileToReplaces;

  bool isNullibityAnnotated(const QualType &QT) {
    if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr())) {
      if (AType->getImmediateNullability() != None) {
        return true;
      }
    }
    return false;
  }

  bool isCandidate(const QualType &QT) {
    return QT->isPointerType() && !isNullibityAnnotated(QT);
  }

  bool isCandidate(const VarDecl *VD) {
    // Don't annotate a decl from a system header
    SourceLocation Loc = VD->getLocation();
    if (Loc.isValid() &&
        (Context.getSourceManager().isInSystemHeader(Loc) ||
         Context.getSourceManager().isInExternCSystemHeader(Loc))) {
      return false;
    }
    return isCandidate(VD->getType());
  }

  bool isNonNull(QualType QT) {
    // Check if this type is already annotated with non-null
    if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr())) {
      if (AType->getNullability(Context) == NullabilityKind::NonNull) {
        return true;
      }
    }

    return false;
  }

  bool isNonNull(const VarDecl *VD) {
    // Check the type
    if (isNonNull(VD->getType())) {
      return true;
    }

    // Check if it is in our map as non-null
    auto D = PtrVars.find(VD);
    if (D != PtrVars.end()) {
      if (D->second == NullabilityKind::NonNull) {
        return true;
      }
    }

    return false;
  }

  bool isNonNull(const Expr *E) {
    // We can ignore casts that do not involve nullability
    while (const CastExpr *CE = dyn_cast<CastExpr>(E)) {
      if (isNullibityAnnotated(E->getType()))
        break;
      E = CE->getSubExpr();
    }

    // Check if this expression's type is already annotated with non-null
    if (isNonNull(E->getType())) {
      return true;
    }

    // Check if the referenced decl has been identified as non-null
    if (const DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
      if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (isNonNull(VD)) {
          return true;
        }
      }
    }

    return false;
  }

  bool isNonNullCompatible(Expr const *E) {
    // Is the expression non-null annotated
    if (isNonNull(E)) {
      return true;
    }

    // Strip off
    Expr const *Stripped = E->IgnoreParenImpCasts();

    // Is the expr taking an address of an object?
    if (auto UO = dyn_cast<UnaryOperator>(Stripped)) {
      if (UO->getOpcode() == UO_AddrOf) {
        return true;
      }
    }

    // Is the expr an array (ArrayToPointerDecay)?
    if (isa<ConstantArrayType>(Stripped->getType())) {
      return true;
    }

    // Is the expr a function
    if (isa<FunctionType>(Stripped->getType())) {
      return true;
    }

    return false;
  }

  void annotate(const VarDecl *VD, NullabilityKind Kind) {
    // If '-params-only' flag is used, only annotate function parameters
    if (ParamsOnly && dyn_cast<ParmVarDecl>(VD) == NULL) {
      return;
    }
    PtrVars[VD] = Kind;
  }

  void makeNonNull(const VarDecl *VD) {
    if (isCandidate(VD)) {
      // If this variable is not already in the list, add it now as non-null
      auto D = PtrVars.find(VD);
      if (D == PtrVars.end()) {
        annotate(VD, NullabilityKind::NonNull);
      }
    }
  }

  void makeNonNull(const DeclRefExpr *DRE) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      makeNonNull(VD);
    }
  }

  void makeNullable(const VarDecl *VD) {
    if (isCandidate(VD)) {
      annotate(VD, NullabilityKind::Nullable);
    }
  }

  void makeNullable(const DeclRefExpr *DRE) {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      makeNullable(VD);
    }
  }

  // Has this function been annotated for nullability?
  bool isUnannotated(const FunctionDecl *FD) {
    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      if (isCandidate(Param)) {
        return true;
      }
    }

    return false;
  }

  void createReturnValueReplacement(FunctionDecl *FD, bool NonNull) {
    StringRef Annotation = " _Nonnull ";
    if (!NonNull) {
      Annotation = " _Nullable ";
    }

    Replacement Rep(Context.getSourceManager(),
                    FD->getReturnTypeSourceRange().getEnd().getLocWithOffset(1),
                    0, Annotation);
    llvm::Error Err = FileToReplaces[Rep.getFilePath()].add(Rep);
    if (Err) {
      llvm::errs() << "replacement failed: " << llvm::toString(std::move(Err))
                   << "\n";
    }
  }

  void createVarDeclReplacements() {
    for (auto const &x : PtrVars) {
      const VarDecl *VD = x.first;
      NullabilityKind Kind = x.second;

      StringRef Annotation = " _Nonnull ";
      if (Kind == NullabilityKind::Nullable) {
        Annotation = " _Nullable ";
      }

      Replacement Rep(Context.getSourceManager(), VD->getLocation(), 0,
                      Annotation);
      llvm::Error Err = FileToReplaces[Rep.getFilePath()].add(Rep);
      if (Err) {
        llvm::errs() << "replacement failed: " << llvm::toString(std::move(Err))
                     << "\n";
      }
    }
  }
};

class SecurifyConsumer : public clang::ASTConsumer {
public:
  explicit SecurifyConsumer(
      std::map<std::string, tooling::Replacements> &FileToReplaces)
      : FileToReplaces(FileToReplaces) {}

  virtual void HandleTranslationUnit(clang::ASTContext &Context) {
    SecurifyVisitor Visitor(Context, FileToReplaces);
    Visitor.SecurifyDecl(Context.getTranslationUnitDecl());
  }

private:
  std::map<std::string, tooling::Replacements> &FileToReplaces;
};

struct SecurifyConsumerFactory {
  SecurifyConsumerFactory(
      std::map<std::string, tooling::Replacements> &FileToReplaces)
      : FileToReplaces(FileToReplaces){};
  std::unique_ptr<ASTConsumer> newASTConsumer() {
    std::unique_ptr<ASTConsumer> Consumer(new SecurifyConsumer(FileToReplaces));
    return Consumer;
  }
  std::map<std::string, tooling::Replacements> &FileToReplaces;
};

int main(int argc, const char **argv) {
  CommonOptionsParser op(argc, argv, SecurifyCategory);
  RefactoringTool Tool(op.getCompilations(), op.getSourcePathList());

  SecurifyConsumerFactory ConsumerFactory(Tool.getReplacements());

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
