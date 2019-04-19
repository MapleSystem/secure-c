#include "clang/Tooling/CommonOptionsParser.h"
#include <clang/Driver/Options.h>
#include <llvm/Option/Arg.h>
#include <llvm/Option/ArgList.h>
#include <llvm/Option/OptTable.h>
#include <llvm/Support/raw_ostream.h>

#include <memory>

using namespace llvm;
using namespace llvm::opt;
using namespace clang;
using namespace clang::driver;

int main(int argc_, char *argv_[]) {
  SmallVector<const char *, 256> argv(argv_, argv_ + argc_);
  std::unique_ptr<OptTable> OptTable(driver::createDriverOptTable());

  if (std::getenv("SECURE_C") == nullptr) {
    errs()
        << "Please set 'SECURE_C' environment variable to the secure-c repo.\n";
    return 1;
  }

  unsigned int MissingArgIndex;
  unsigned int MissingArgCount = 0;
  ArrayRef<const char *> Argv = argv;
  InputArgList Args(
      OptTable->ParseArgs(Argv.slice(1), MissingArgIndex, MissingArgCount));

  std::string SecureCFlags = "";
  std::string CompilerCmd = "clang";
  std::string Inputs;
  raw_string_ostream InputsStream(Inputs);
  std::string CompilerFlags;
  raw_string_ostream CompilerFlagsStream(CompilerFlags);

  for (Arg *arg : Args) {
    if (arg->getOption().getKind() == Option::UnknownClass) {
      std::string ArgString = arg->getAsString(Args);
      size_t EqualsLoc = ArgString.find('=');
      if (EqualsLoc != std::string::npos) {
        if (ArgString.substr(0, EqualsLoc) == "-secure-c-flags") {
          SecureCFlags = ArgString.substr(EqualsLoc + 1);
          continue;
        } else if (ArgString.substr(0, EqualsLoc) == "-cc") {
          CompilerCmd = ArgString.substr(EqualsLoc + 1);
          continue;
        }
      }
      errs() << "Unknown argument: " << arg->getSpelling() << "\n";
      return 1;
    }

    if (arg->getOption().getKind() == Option::InputClass) {
      InputsStream << arg->getAsString(Args) << " ";
    } else {
      std::string s = arg->getAsString(Args);
      if (s[0] == '/')
        s[0] = '-';
      CompilerFlagsStream << s << " ";
    }
  }

  InputsStream.flush();
  CompilerFlagsStream.flush();

  std::string SecureCCmd =
      "secure-c " + SecureCFlags + " " + Inputs +
      "-- -ferror-limit=0 "
      "-include $SECURE_C/clang/tools/securify/known_symbols.h "
      "-I $SECURE_C/clang/tools/secure-c " +
      CompilerFlags;

  outs() << SecureCCmd << "\n";
  int rc = system(SecureCCmd.c_str());
  if (rc) {
    return rc;
  }

  CompilerCmd += " -I $SECURE_C/clang/tools/secure-c " + CompilerFlags + Inputs;

  outs() << CompilerCmd << "\n";
  return system(CompilerCmd.c_str());
}
