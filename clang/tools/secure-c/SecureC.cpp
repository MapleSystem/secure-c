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

  bool shouldTraversePostOrder() { return true; }

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

  bool TraverseFunctionDecl(FunctionDecl *FD) {
    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      const QualType QT = Param->getType();
      if (dyn_cast<PointerType>(QT.getTypePtr())) {
        if (!isNullibityAnnotated(QT)) {
          reportUnannotatedParam(FD, Param, false, *Context);
        }
      }
    }

    // Create a function scope for checked decls
    CheckedDecls.push_back(std::map<Decl *, bool>());

    RecursiveASTVisitor<SecureCVisitor>::TraverseFunctionDecl(FD);

    // Remove the function scoped checked decls
    CheckedDecls.pop_back();

    return true;
  }

  bool TraverseIfStmt(IfStmt *If) {
    CheckedDecls.push_back(std::map<Decl *, bool>());

    if (If->hasInitStorage()) {
      TraverseStmt(If->getInit());
    }

    if (If->hasVarStorage()) {
      TraverseStmt(If->getConditionVariableDeclStmt());
    }

    TraverseStmt(If->getCond());
    TraverseStmt(If->getThen());

    if (If->hasElseStorage()) {
      // In the else case, the values are switched
      // (decls known to be NULL in the if body are non-null in the else)
      for (auto it = CheckedDecls.back().begin();
           it != CheckedDecls.back().end(); ++it) {
        it->second = !it->second;
      }
      TraverseStmt(If->getElse());
    }
    CheckedDecls.pop_back();

    return true;
  }

  bool VisitBinaryOperator(BinaryOperator *BO) {
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      // x == NULL OR x != NULL
      if (BO->getRHS()->isNullPointerConstant(
              *Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *LHS =
                dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
          CheckedDecls.back()[LHS->getDecl()] = BO->getOpcode() == BO_EQ;
        }
      }
      // NULL == x OR NULL != x
      if (BO->getLHS()->isNullPointerConstant(
              *Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *RHS =
                dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
          CheckedDecls.back()[RHS->getDecl()] = BO->getOpcode() == BO_EQ;
        }
      }

      return true;
    }

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

  bool VisitMemberExpr(MemberExpr *ME) {
    Expr *Base = ME->getBase();
    if (!isNonnullCompatible(Base)) {
      reportIllegalAccess(Base->getType(), ME, *Context);
    }

    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->getOpcode() != UO_Deref) {
      return true;
    }
    if (DeclRefExpr *DRE =
            dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts())) {
      if (!isNonnullCompatible(DRE)) {
        reportIllegalAccess(DRE->getType(), UO, *Context);
      }
    }

    return true;
  }

  bool VisitReturnStmt(ReturnStmt *RS) {
    // If we return inside of an if stmt, put the inverse of the if's checked
    // decls into the function scope. For example:
    //   if (x == NULL) { return 0; }
    // After this if stmt, we are sure that x is non-null for the rest of the
    // function.
    if (CheckedDecls.size() > 1) {
      std::map<Decl *, bool> &IfScope = CheckedDecls.back();
      std::map<Decl *, bool> &FuncScope = CheckedDecls.front();
      for (auto const &CD : IfScope) {
        FuncScope[CD.first] = !CD.second;
      }
    }
    return true;
  }

private:
  ASTContext *Context;

  // Decls that have been checked in this scope.
  // true = known to be NULL, false = known to be non-NULL
  std::vector<std::map<Decl *, bool>> CheckedDecls;

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

  void reportIllegalAccess(const QualType &Ty, const Expr *E,
                           const ASTContext &Context) {
    auto &DE = Context.getDiagnostics();
    const auto ID =
        DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                           "illegal access of nullable pointer type '%0'");

    auto DB = DE.Report(E->getBeginLoc(), ID);
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
                                       "with either '_Nonnull' or '_Nullable'");

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

  bool isNonnullCompatible(Expr const *E) {
    // Strip off
    Expr const *Stripped = E->IgnoreParenImpCasts();

    // Is the expr attributed with nonnull?
    if (isNonnull(Stripped->getType())) {
      return true;
    }

    // Is the expr taking an address of an object?
    if (auto UO = dyn_cast<clang::UnaryOperator>(Stripped)) {
      if (UO->getOpcode() == UO_AddrOf) {
        return true;
      }
    }

    // Is the expr referring to a known non-null decl?
    if (DeclRefExpr const *DRE = dyn_cast<DeclRefExpr>(Stripped)) {
      Decl const *D = DRE->getDecl();
      for (auto const &CDMap : CheckedDecls) {
        for (auto const &CD : CDMap) {
          if (D == CD.first) {
            return !CD.second;
          }
        }
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
