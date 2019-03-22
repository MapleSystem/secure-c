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

class NullScope {
  // Decls that have been checked (with if-stmt) in this scope.
  // true = known to be NULL, false = known to be non-NULL
  std::map<Decl *, bool> CheckedDecls;
  // Decls that are either assigned in this scope, or checked
  // in a child scope with early returns.
  std::map<Decl *, bool> localDecls;
  // Whether we are certain of CheckedDecls or not.
  // For example, uncertain for condition is "p == NULL || q == NULL".
  // Only matters when there are >1 decls in the scope.
  bool Certain;
  // whether the if-condition is compound (by OR/AND)
  bool Compound;
  // Whether we have seen a return statement in this scope
  bool Returned;

public:
  NullScope() : Certain(true), Compound(false), Returned(false){};
  void setCheckedNullability(Decl *D, bool isNull) { CheckedDecls[D] = isNull; }
  void setLocalNullability(Decl *D, bool isNull) { localDecls[D] = isNull; }
  void cleanLocalNullability() { localDecls = {}; }
  void setUncertain(bool uncertain) { Certain = !uncertain; }
  bool isCertain() { return Certain; }
  void setReturned() { Returned = true; }
  void setCompound() { Compound = true; }
  bool hasReturned() { return Returned; }

  // Return true if we definitely know D is not null.
  bool isNotNull(const Decl *D) {
    if (Certain) {
      for (auto it : CheckedDecls) {
        if (it.first == D) {
          return !it.second;
        }
      }
    }
    // The merged DECLs are considered Certain
    for (auto it : localDecls) {
      if (it.first == D) {
        return !it.second;
      }
    }
    return false;
  }

  // Return true if we definitely know D is null.
  bool isNull(const Decl *D) {
    if (Certain) {
      for (auto it : CheckedDecls) {
        if (it.first == D) {
          return it.second;
        }
      }
    }
    // The merged DECLs are considered Certain
    for (auto it : localDecls) {
      if (it.first == D) {
        return it.second;
      }
    }
    return false;
  }

  void inverse() {
    for (auto it : CheckedDecls) {
      CheckedDecls[it.first] = !it.second;
    }
    if (Compound)
      Certain = !Certain;
  }

  void merge(NullScope &ns) {
    if (ns.isCertain()) {
      for (auto kv : ns.CheckedDecls) {
        localDecls[kv.first] = kv.second;
      }
    }
  }
};

class SecureCVisitor : public RecursiveASTVisitor<SecureCVisitor> {
public:
  explicit SecureCVisitor(
      ASTContext &Context,
      std::map<std::string, tooling::Replacements> &FileToReplaces)
      : Context(Context), FileToReplaces(FileToReplaces) {
    // Create an initial scope for globals
    NullScopes.push_back(llvm::make_unique<NullScope>());
  }

  bool shouldTraversePostOrder() { return true; }

  bool TraverseDecl(Decl *D) {
    // Don't traverse Decl in system header files or not in source files
    SourceLocation Loc = D->getLocation();
    if (Loc.isValid() &&
        (Context.getSourceManager().isInSystemHeader(Loc) ||
         Context.getSourceManager().isInExternCSystemHeader(Loc))) {
      return true;
    }

    RecursiveASTVisitor<SecureCVisitor>::TraverseDecl(D);
    return true;
  }

  bool VisitVarDecl(VarDecl *VD) {
    if (isa<ParmVarDecl>(VD))
      return true;

    if (VD->hasInit()) {
      const Expr *Init = VD->getInit();
      if (isNonnull(VD->getType())) {
        // A non-null pointer must be initialized with a non-null expression
        if (!isNonnullCompatible(Init)) {
          reportIllegalCast(VD->getType(), Init, Context);
        }
      } else {
        // Track the local nullability of this variable
        bool nonNull = isNonnullCompatible(Init);
        NullScopes.back()->setLocalNullability(VD, !nonNull);
      }
    } else if (isNonnull(VD->getType()) && !VD->hasExternalStorage()) {
      // Non-null variables must be initialized
      reportUninitializedNonnull(VD, Context);
    }

    return true;
  }

  bool TraverseFunctionDecl(FunctionDecl *FD) {
    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      const QualType QT = Param->getType();
      if (dyn_cast<PointerType>(QT.getTypePtr())) {
        if (!DefaultNullable && !isNullibityAnnotated(QT)) {
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

  bool TraverseIfStmt(IfStmt *If) {
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

  bool VisitBinaryOperator(BinaryOperator *BO) {
    // TODO: check if we are inside an if-condition, rather than e.g. "b = p
    // != NULL"
    if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
      // x == NULL OR x != NULL
      if (BO->getRHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *LHS =
                dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
          NullScopes.back()->setCheckedNullability(LHS->getDecl(),
                                                   BO->getOpcode() == BO_EQ);
        }
      }
      // NULL == x OR NULL != x
      if (BO->getLHS()->isNullPointerConstant(
              Context, Expr::NPC_NeverValueDependent) != Expr::NPCK_NotNull) {
        if (DeclRefExpr *RHS =
                dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
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

  bool VisitAssign(Expr *LHS, Expr *RHS) {
    // case 1: assign nullable to a nonnull typed pointer =>
    // complain!
    if (isNonnull(LHS->getType())) {
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

  bool VisitCallExpr(CallExpr *CE) {
    const DeclRefExpr *DRE =
        dyn_cast<DeclRefExpr>(CE->getCallee()->IgnoreParenImpCasts());
    if (!DRE)
      return true;

    // If the callee is a variable (function pointer), it should be non-null
    if (const VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
      if (!isNonnullCompatible(DRE)) {
        reportIllegalAccess(DRE, CE, Context);
      }
    }

    const FunctionDecl *FD = dyn_cast<FunctionDecl>(DRE->getDecl());
    if (FD == NULL) {
      return true;
    }

    for (unsigned int i = 0; i < FD->getNumParams(); i++) {
      const ParmVarDecl *Param = FD->getParamDecl(i);
      if (isNonnull(Param->getType())) {
        const Expr *Arg = CE->getArg(i);
        if (!isNonnullCompatible(Arg)) {
          reportIllegalCast(Param->getType(), Arg, Context);
        }
      }
    }
    return true;
  }

  bool VisitMemberExpr(MemberExpr *ME) {
    Expr *Base = ME->getBase();
    if (ME->isArrow() && !isNonnullCompatible(Base)) {
      reportIllegalAccess(Base, ME, Context);
    }

    return true;
  }

  bool VisitArraySubscriptExpr(ArraySubscriptExpr *AE) {
    Expr *Base = AE->getBase();
    if (!isNonnullCompatible(Base)) {
      reportIllegalAccess(Base, AE, Context);
    }

    return true;
  }

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->getOpcode() != UO_Deref) {
      return true;
    }
    auto expr = UO->getSubExpr()->IgnoreParenImpCasts();
    if (!isNonnullCompatible(expr)) {
      reportIllegalAccess(expr, UO, Context);
    }

    return true;
  }

  bool VisitReturnStmt(ReturnStmt *RS) {
    NullScopes.back()->setReturned();
    return true;
  }

private:
  ASTContext &Context;

  std::vector<std::unique_ptr<NullScope>> NullScopes;

  std::map<std::string, tooling::Replacements> &FileToReplaces;

  void insertRuntimeCheck(const Expr *Pointer) {
    QualType Ty = Pointer->getType();
    std::string TyString = Ty.getAsString();
    // If the type is already annotated, strip the annotation
    if (isNullibityAnnotated(Ty)) {
      AttributedType::stripOuterNullability(Ty);
      TyString = Ty.getAsString();
    }

    // Get the original pointer expression as a string
    std::string PtrExprString;
    llvm::raw_string_ostream stream(PtrExprString);

    Pointer->printPretty(stream, NULL, Context.getPrintingPolicy());
    // Flush ostream buffer.
    stream.flush();

    std::string ReplacementText =
        "(" + TyString +
        " _Nonnull)(_CheckNonNull(__FILE__, __LINE__, __extension__ "
        "__PRETTY_FUNCTION__, " +
        PtrExprString + "))";
    Replacement Rep(Context.getSourceManager(), Pointer, ReplacementText);

    // Include the Secure-C header once in each modified file
    if (FileToReplaces[Rep.getFilePath()].empty()) {
      Replacement Header(Rep.getFilePath(), 0, 0, "#include <secure_c.h>\n");
      llvm::Error Err = FileToReplaces[Rep.getFilePath()].add(Header);
      if (Err) {
        llvm::errs() << "replacement failed: " << llvm::toString(std::move(Err))
                     << "\n";
      }
    }

    llvm::Error Err = FileToReplaces[Rep.getFilePath()].add(Rep);
    if (Err) {
      llvm::errs() << "replacement failed: " << llvm::toString(std::move(Err))
                   << "\n";
    }
  }

  void reportIllegalCast(const QualType &Ty, const Expr *Pointer,
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

  void reportIllegalAccess(const Expr *Pointer, const Expr *Access,
                           const ASTContext &Context) {
    auto &DE = Context.getDiagnostics();
    auto ID =
        DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                           "illegal access of nullable pointer type '%0'");

    // In debug mode, we insert a run-time check into the code
    if (RunMode == debug) {
      insertRuntimeCheck(Pointer);
      ID = DE.getCustomDiagID(
          clang::DiagnosticsEngine::Remark,
          "illegal access of nullable pointer type, inserting run-time check");
    }

    auto DB = DE.Report(Access->getBeginLoc(), ID);
    DB.AddString(Pointer->getType().getAsString());

    const auto Range =
        clang::CharSourceRange::getCharRange(Access->getSourceRange());
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

  void reportUninitializedNonnull(const VarDecl *VD,
                                  const ASTContext &Context) {
    auto &DE = Context.getDiagnostics();
    const auto ID = DE.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                       "Nonnull pointer is not initialized");

    auto DB = DE.Report(VD->getTypeSpecStartLoc(), ID);
    const auto Range =
        clang::CharSourceRange::getCharRange(VD->getSourceRange());
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

    if (isa<ConstantArrayType>(Stripped->getType())) // e.g. a literal string
      return true;

    // Is the expr a function?
    if (isa<FunctionType>(Stripped->getType())) {
      return true;
    }

    // Is the expr referring to a known non-null decl?
    if (DeclRefExpr const *DRE = dyn_cast<DeclRefExpr>(Stripped)) {
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
};

class SecureCConsumer : public clang::ASTConsumer {
public:
  explicit SecureCConsumer(

      std::map<std::string, tooling::Replacements> &FileToReplaces)
      : FileToReplaces(FileToReplaces) {}

  virtual void HandleTranslationUnit(clang::ASTContext &Context) {
    SecureCVisitor Visitor(Context, FileToReplaces);
    Visitor.TraverseDecl(Context.getTranslationUnitDecl());
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
