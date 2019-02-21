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
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Refactoring.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;
static llvm::cl::OptionCategory SecureCCategory("Secure-C Compiler");

class SecureCVisitor : public RecursiveASTVisitor<SecureCVisitor> {
public:
  explicit SecureCVisitor(ASTContext *Context) : Context(Context) {}

  bool TraverseDecl(Decl *D) {
    // Don't traverse in system header files
    SourceLocation Loc = D->getLocation();
    if (Loc.isValid() &&
        (Context->getSourceManager().isInSystemHeader(Loc) ||
         Context->getSourceManager().isInExternCSystemHeader(Loc))) {
      return true;
    }

    RecursiveASTVisitor<SecureCVisitor>::TraverseDecl(D);
    return true;
  }

  bool VisitFunctionDecl(FunctionDecl *FD) {
    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      const QualType QT = Param->getType();
      if (dyn_cast<PointerType>(QT.getTypePtr())) {
        if (!isNullibityAnnotated(QT)) {
          reportUnannotatedParam(FD, Param, false, *Context);
        }
      }
    }

    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() != BO_Assign) {
      return true;
    }
    const Expr *LHS = BO->getLHS();

    if (isNonnull(LHS->getType())) {
      const Expr *RHS = BO->getRHS();
      if (!isNonnullCompatible(RHS)) {
        reportIllegalCast(LHS->getType(), RHS, *Context);
      }
    }
    return true;
  }

  bool VisitCallExpr(CallExpr *CE) {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (FD == NULL) {
      return true;
    }

    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      if (isNonnull(Param->getType())) {
        const Expr *Arg = CE->getArg(i);
        if (!isNonnullCompatible(Arg)) {
          reportIllegalCast(Param->getType(), Arg, *Context);
        }
      }
    }
    return true;
  }

private:
  ASTContext *Context;

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

  void reportUnannotatedParam(const FunctionDecl *FD, const ParmVarDecl *Param,
                              bool suggestNonnull, const ASTContext &Context) {
    auto &DE = Context.getDiagnostics();
    const auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                       "pointer parameter is not annotated "
                                       "with either `_Nonnull` or `_Nullable`");

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
};

class SecureCConsumer : public clang::ASTConsumer {
public:
  explicit SecureCConsumer(ASTContext *Context) : Visitor(Context) {}

  virtual void HandleTranslationUnit(clang::ASTContext &Context) {
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
  }

private:
  SecureCVisitor Visitor;
};

class SecureCAction : public clang::ASTFrontendAction {
public:
  virtual std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
    return std::unique_ptr<clang::ASTConsumer>(
        new SecureCConsumer(&Compiler.getASTContext()));
  }
};

int main(int argc, const char **argv) {
  CommonOptionsParser op(argc, argv, SecureCCategory);
  RefactoringTool Tool(op.getCompilations(), op.getSourcePathList());

  if (int Result = Tool.run(newFrontendActionFactory<SecureCAction>().get())) {
    return Result;
  }

  return 0;
}
