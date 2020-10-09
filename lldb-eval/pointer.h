/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LLDB_EVAL_POINTER_H_
#define LLDB_EVAL_POINTER_H_

#include "lldb-eval/scalar.h"
#include "lldb/API/SBType.h"
#include "lldb/API/SBValue.h"

namespace lldb_eval {

class Pointer {
 public:
  Pointer() : addr_(0) {}
  Pointer(uint64_t addr, lldb::SBType type) : addr_(addr), type_(type) {}

  uint64_t addr() const { return addr_; }
  lldb::SBType type() const { return type_; }

  bool IsPointerToVoid();

  bool AsBool() const;

  Pointer Add(int64_t offset);

  static Pointer FromSbValue(lldb::SBValue value);

 private:
  uint64_t addr_;
  lldb::SBType type_;
};

}  // namespace lldb_eval

#endif  // LLDB_EVAL_POINTER_H_
