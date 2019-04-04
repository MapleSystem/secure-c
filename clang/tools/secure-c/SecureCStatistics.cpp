#include "SecureCStatistics.h"

#include "clang/AST/AST.h"
#include "llvm/Support/raw_ostream.h"

#include "SecureC.h"

SecureCStatistics::SecureCStatistics(SecureCVisitor *SCV) : SCV(SCV) {}

void SecureCStatistics::trackStatistics(const Expr *E, PtrContext Context) {
  if (!checkPointer(E))
    return;

  switch (Context) {
  case deref:
    ++Dereferences;
    break;
  case member:
    ++MemberAccesses;
    break;
  case subscript:
    ++ArraySubscripts;
    break;
  case call:
    ++FunctionCalls;
    break;
  case cast:
    ++Casts;
    break;
  }
}

void SecureCStatistics::insertCheck() { ++ChecksInserted; }

void SecureCStatistics::duplicateCheck() {
  --ChecksInserted;
  ++DuplicateChecks;
}

void SecureCStatistics::redundantCheck() { ++RedundantChecks; }

void SecureCStatistics::reportStatistics(bool DebugMode) {
  llvm::outs() << "----------------------------------------\n";
  llvm::outs() << "Secure-C Statistics:\n";
  llvm::outs() << "  Potentially dangerous pointer uses:\n";
  llvm::outs() << "    Subscripts:      " << ArraySubscripts << "\n";
  llvm::outs() << "    Dereferences:    " << Dereferences << "\n";
  llvm::outs() << "    Function calls:  " << FunctionCalls << "\n";
  llvm::outs() << "    Member accesses: " << MemberAccesses << "\n";
  llvm::outs() << "    Casts:           " << Casts << "\n";
  llvm::outs() << "  Total pointer uses: "
               << ArraySubscripts + Dereferences + FunctionCalls +
                      MemberAccesses + Casts
               << "\n";
  llvm::outs() << "  Analysis:\n";
  llvm::outs() << "    Safe by annotation: " << SafeByAnnotation << "\n";
  llvm::outs() << "    Safe by analysis:   " << SafeByAnalysis << "\n";
  llvm::outs() << "    Duplicates:         " << DuplicateChecks << "\n";
  if (DebugMode) {
    llvm::outs() << "    Checks inserted:    " << ChecksInserted << "\n";
  }
  llvm::outs() << "  Redundant checks: " << RedundantChecks << "\n";
  llvm::outs() << "----------------------------------------\n";
}

bool SecureCStatistics::checkPointer(const Expr *E) {
  if (!E->getType()->isPointerType())
    return false;

  // Strip off
  Expr const *Stripped = E->IgnoreParenImpCasts();

  // Is the expr taking an address of an object?
  if (auto UO = dyn_cast<clang::UnaryOperator>(Stripped))
    if (UO->getOpcode() == UO_AddrOf)
      return false;

  // Is the expr a constant array, e.g. a literal string?
  if (isa<ConstantArrayType>(Stripped->getType()))
    return false;

  // Is the expr a function?
  if (isa<FunctionType>(Stripped->getType()))
    return false;

  // Is the expr attributed with nonnull?
  if (isAnnotatedNonnull(Stripped->getType()))
    ++SafeByAnnotation;

  // Is the expr referring to a known non-null decl?
  if (SCV->isDeterminedNonNull(Stripped))
    ++SafeByAnalysis;

  return true;
}
