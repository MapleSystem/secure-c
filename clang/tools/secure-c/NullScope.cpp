#include "NullScope.h"

NullScope::NullScope() : Certain(true), Compound(false), Returned(false){};
void NullScope::setCheckedNullability(Decl *D, bool isNull) {
  CheckedDecls[D] = isNull;
}
void NullScope::setLocalNullability(Decl *D, bool isNull) {
  localDecls[D] = isNull;
}
void NullScope::cleanLocalNullability() { localDecls = {}; }
void NullScope::setUncertain(bool uncertain) { Certain = !uncertain; }
bool NullScope::isCertain() { return Certain; }
void NullScope::setReturned() { Returned = true; }
void NullScope::setCompound() { Compound = true; }
bool NullScope::hasReturned() { return Returned; }

// Return true if we definitely know D is not null.
bool NullScope::isNotNull(const Decl *D) {
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
bool NullScope::isNull(const Decl *D) {
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

void NullScope::inverse() {
  for (auto it : CheckedDecls) {
    CheckedDecls[it.first] = !it.second;
  }
  if (Compound)
    Certain = !Certain;
}

void NullScope::merge(NullScope &ns) {
  if (ns.isCertain()) {
    for (auto kv : ns.CheckedDecls) {
      localDecls[kv.first] = kv.second;
    }
  }
}
