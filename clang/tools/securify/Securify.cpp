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
    Overwrite("overwrite",
              llvm::cl::desc("Overwrite the source file with the changes."),
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
    createReplacements();
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
    bool ret = RecursiveASTVisitor<SecurifyVisitor>::TraverseFunctionDecl(FD);

    // If this is a declaration (with no body), save it to be updated after
    // processing the definition
    if (!FD->doesThisDeclarationHaveABody()) {
      SavedFuncDecls[FD->getName()] = FD;
      return ret;
    }

    // Parameters that were not annotated should be marked with default
    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      if (isCandidate(Param->getType())) {
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

    // Check if there is a saved declaration that we should update
    auto Found = SavedFuncDecls.find(FD->getName());
    if (Found != SavedFuncDecls.end()) {
      FunctionDecl *Saved = Found->second;
      for (unsigned int i = 0; i < FD->getNumParams(); i++) {
        const ParmVarDecl *SavedParam = Saved->getParamDecl(i);
        if (isCandidate(SavedParam->getType())) {
          // If it is already annotated, leave it as-is
          const QualType QT = SavedParam->getType();
          if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr())) {
            auto NK = AType->getNullability(Context);
            if (NK.hasValue()) {
              continue;
            }
          }
          const ParmVarDecl *Param = FD->getParamDecl(i);
          if (isNonNull(Param)) {
            makeNonNull(SavedParam);
          } else {
            makeNullable(SavedParam);
          }
        }
      }
    }

    return ret;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      // x == NULL OR x != NULL
      if (isCandidate(BO->getLHS()->getType()) &&
          BO->getRHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *LHS =
                dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
          // If this variable is not in the list, add it now
          if (VarDecl *VD = dyn_cast<VarDecl>(LHS->getDecl())) {
            auto D = PtrVars.find(VD);
            if (D == PtrVars.end()) {
              // If this is a null-check inside an assert, assume non-null
              if (TraversingAssert && BO->getOpcode() == BO_NE) {
                makeNonNull(VD);
              } else {
                // else, assume nullable
                makeNullable(VD);
              }
            }
          }
        }
      }
      // NULL == x OR NULL != x
      if (isCandidate(BO->getRHS()->getType()) &&
          BO->getLHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *RHS =
                dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
          // If this variable is not in the list, add it now
          if (VarDecl *VD = dyn_cast<VarDecl>(RHS->getDecl())) {
            auto D = PtrVars.find(VD);
            if (D == PtrVars.end()) {
              // If this is a null-check inside an assert, assume non-null
              if (TraversingAssert && BO->getOpcode() == BO_NE) {
                makeNonNull(VD);
              } else {
                // else, assume nullable
                makeNullable(VD);
              }
            }
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
          // If this variable is not in the list, add it now as assumed non-null
          if (VarDecl *VD = dyn_cast<VarDecl>(RHS->getDecl())) {
            auto D = PtrVars.find(VD);
            if (D == PtrVars.end()) {
              makeNonNull(VD);
            }
          }
        }
      }

      // Assigning NULL to a pointer (assume nullable)
      if (isCandidate(BO->getLHS()->getType()) &&
          BO->getRHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *LHS =
                dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
          if (VarDecl *VD = dyn_cast<VarDecl>(LHS->getDecl())) {
            makeNullable(VD);
          }
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
    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD == NULL) {
      return true;
    }

    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      // Check for non-null parameters
      if (isNonNull(Param)) {
        if (DeclRefExpr *DRE =
                dyn_cast<DeclRefExpr>(CE->getArg(i)->IgnoreParenImpCasts())) {
          if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
            // If this variable is not in the list, add it now as assumed
            // non-null
            auto D = PtrVars.find(VD);
            if (D == PtrVars.end()) {
              makeNonNull(VD);
            }
          }
        }
      }
    }
    return true;
  }

  bool VisitMemberExpr(MemberExpr *ME) {
    if (DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(ME->getBase()->IgnoreParenImpCasts())) {
      if (isCandidate(DRE->getType())) {
        // If this variable is not in the list, add it now as assumed non-null
        if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          auto D = PtrVars.find(VD);
          if (D == PtrVars.end()) {
            makeNonNull(VD);
          }
        }
      }
    }

    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->getOpcode() != UO_Deref) {
      return true;
    }
    if (DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts())) {
      // If this variable is not in the list, add it now as assumed non-null
      if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        auto D = PtrVars.find(VD);
        if (D == PtrVars.end()) {
          makeNonNull(VD);
        }
      }
    }

    return true;
  }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *ASE) {
    if (DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(ASE->getBase()->IgnoreParenImpCasts())) {
      if (isCandidate(DRE->getType())) {
        if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
          // If this variable is not in the list, add it now as assumed non-null
          auto D = PtrVars.find(VD);
          if (D == PtrVars.end()) {
            makeNonNull(VD);
          }
        }
      }
    }

    return true;
  }

  bool VisitDeclStmt(DeclStmt *DS) {
    for (auto DI = DS->decl_begin(); DI != DS->decl_end(); ++DI) {
      if (VarDecl *VD = dyn_cast<VarDecl>(*DI)) {
        // If it is not a pointer, or it is already annotated, skip it
        if (!isCandidate(VD->getType()) ||
            isNullibityAnnotated(VD->getType())) {
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

private:
  ASTContext &Context;

  // Pointers that have been identified
  std::map<const VarDecl *, NullabilityKind> PtrVars =
      std::map<const VarDecl *, NullabilityKind>();

  std::map<StringRef, FunctionDecl *> SavedFuncDecls =
      std::map<StringRef, FunctionDecl *>();

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

    // Is the expr a string literal?
    if (dyn_cast<StringLiteral>(Stripped)) {
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
    annotate(VD, NullabilityKind::NonNull);
  }
  void makeNullable(const VarDecl *VD) {
    annotate(VD, NullabilityKind::Nullable);
  }

  void createReplacements() {
    for (auto const &x : PtrVars) {
      const VarDecl *VD = x.first;
      NullabilityKind Kind = x.second;

      StringRef Annotation = " _Nonnull ";
      if (Kind == NullabilityKind::Nullable) {
        Annotation = " _Nullable ";
      }

      Replacement Rep(
          Context.getSourceManager(),
          VD->getTypeSourceInfo()->getTypeLoc().getEndLoc().getLocWithOffset(1),
          0, Annotation);
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

  if (Overwrite) {
    if (int Result =
            Tool.runAndSave(newFrontendActionFactory(&ConsumerFactory).get())) {
      return Result;
    }
  } else {
    if (int Result =
            Tool.run(newFrontendActionFactory(&ConsumerFactory).get())) {
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
  }

  return 0;
}
