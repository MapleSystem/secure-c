//------------------------------------------------------------------------------
// Using AST matchers with RefactoringTool. Demonstrates:
//
// * How to use Replacements to collect replacements in a matcher instead of
//   directly applying fixes to a Rewriter.
//
// Eli Bendersky (eliben@gmail.com)
// This code is in the public domain
//------------------------------------------------------------------------------
#include <string>

#include "clang/AST/AST.h"
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
static llvm::cl::OptionCategory SecureCCategory("Secure-C Compiler");

class SecureCCallback : public MatchFinder::MatchCallback {
public:
  SecureCCallback() : Policy(PrintingPolicy(LangOptions())) {}

protected:
  void reportIllegalCast(const QualType &Ty, const Expr *E,
                   const ASTContext &Context) {
    auto &DE = Context.getDiagnostics();
    const auto ID =
        DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                           "implicit conversion from nullable pointer type "
                           "'%0' to non-nullable pointer type '%1'");

    auto DB = DE.Report(E->getBeginLoc(), ID);
    DB.AddString(E->getType().getAsString());
    DB.AddString(Ty.getAsString());

    const auto Range =
        clang::CharSourceRange::getCharRange(E->getSourceRange());
    DB.AddSourceRange(Range);
  }

  void reportUnannotatedParam(const FunctionDecl* FD, const ParmVarDecl *Param, bool suggestNonnull,
                   const ASTContext &Context) {
    auto &DE = Context.getDiagnostics();
    const auto ID =
        DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                           "pointer parameter is not annotated with either `_Nonnull` or `_Nullable`");

    auto DB = DE.Report(Param->getTypeSpecStartLoc(), ID);
    const auto Range =
        clang::CharSourceRange::getCharRange(Param->getSourceRange());
    DB.AddSourceRange(Range);
  }

  bool isNullibityAnnotated(const QualType &QT) {
    if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr())) {
      if (AType->getImmediateNullability() != None) {
        return true;
      }
    }
    return false;
  }

  bool isNonnull(const QualType &QT) {
    if (auto AType = dyn_cast<AttributedType>(QT.getTypePtr())) {
      if (AType->getImmediateNullability() == NullabilityKind::NonNull) {
        return true;
      }
    }
    return false;
  }

  bool isNonnullCompatible(const Expr *E) {
    // Is the arg also attributed with nonnull?
    if (auto attributed = dyn_cast<AttributedType>(E->getType().getTypePtr())) {
      if (attributed->getImmediateNullability() == NullabilityKind::NonNull) {
        return true;
      }
    }

    // Is the arg taking an address of an object?
    if (auto UO = dyn_cast<clang::UnaryOperator>(E)) {
      if (UO->getOpcode() == UO_AddrOf) {
        return true;
      }
    }

    return false;
  }

private:
  PrintingPolicy Policy;
};

class CallExprHandler : public SecureCCallback {
public:
  virtual void run(const MatchFinder::MatchResult &Result) {
    // The matched call expression was bound to 'callExpr'.
    if (const CallExpr *CE =
            Result.Nodes.getNodeAs<clang::CallExpr>("callExpr")) {
      const FunctionDecl *FD = CE->getDirectCallee();
      if (FD == NULL) {
        return;
      }

      for (unsigned int i = 0; i < FD->getNumParams(); i++) {
        const ParmVarDecl *Param = FD->getParamDecl(i);
        if (isNonnull(Param->getType())) {
          const Expr *Arg = CE->getArg(i);
          if (!isNonnullCompatible(Arg)) {
            reportIllegalCast(Param->getType(), Arg, *Result.Context);
          }
        }
      }
    }
  }
};

class BinaryOperatorHandler : public SecureCCallback {
public:
  virtual void run(const MatchFinder::MatchResult &Result) {
    // The matched call expression was bound to 'binOp'.
    if (const BinaryOperator *BO =
            Result.Nodes.getNodeAs<clang::BinaryOperator>("binOp")) {
      if (BO->getOpcode() != BO_Assign) {
        return;
      }
      const Expr *LHS = BO->getLHS();

      if (isNonnull(LHS->getType())) {
        const Expr *RHS = BO->getRHS();
        if (!isNonnullCompatible(RHS)) {
          reportIllegalCast(LHS->getType(), RHS, *Result.Context);
        }
      }
    }
  }
};

class FunctionDeclHandler : public SecureCCallback {
public:
  virtual void run(const MatchFinder::MatchResult &Result) {
    // The matched function declaration was bound to 'funcDecl'.
    if (const FunctionDecl *FD =
            Result.Nodes.getNodeAs<clang::FunctionDecl>("funcDecl")) {
      for (unsigned int i = 0; i < FD->getNumParams(); i++) {
        const ParmVarDecl *Param = FD->getParamDecl(i);
        const QualType QT = Param->getType();
        if (dyn_cast<PointerType>(QT.getTypePtr())) {
          if (!isNullibityAnnotated(QT)) {
            reportUnannotatedParam(FD, Param, false, *Result.Context);
          }
        }
      }
    }
  }
};

int main(int argc, const char **argv) {
  CommonOptionsParser op(argc, argv, SecureCCategory);
  RefactoringTool Tool(op.getCompilations(), op.getSourcePathList());

  // Set up AST matcher callbacks.
  CallExprHandler HandlerForCall;
  BinaryOperatorHandler HandlerForBinOp;
  FunctionDeclHandler HandlerForFD;

  MatchFinder Finder;
  Finder.addMatcher(callExpr().bind("callExpr"), &HandlerForCall);
  Finder.addMatcher(binaryOperator().bind("binOp"), &HandlerForBinOp);
  Finder.addMatcher(functionDecl().bind("funcDecl"), &HandlerForFD);

  // Run the tool and collect a list of replacements. We could call runAndSave,
  // which would destructively overwrite the files with their new contents.
  // However, for demonstration purposes it's interesting to print out the
  // would-be contents of the rewritten files instead of actually rewriting
  // them.
  if (int Result = Tool.run(newFrontendActionFactory(&Finder).get())) {
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

  // Query the rewriter for all the files it has rewritten, dumping their new
  // contents to stdout.
  for (Rewriter::buffer_iterator I = Rewrite.buffer_begin(),
                                 E = Rewrite.buffer_end();
       I != E; ++I) {
    const FileEntry *Entry = Sources.getFileEntryForID(I->first);
    llvm::outs() << "Rewrite buffer for file: " << Entry->getName() << "\n";
    I->second.write(llvm::outs());
  }

  return 0;
}
