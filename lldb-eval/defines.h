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

#ifndef LLDB_EVAL_DEFINES_H_
#define LLDB_EVAL_DEFINES_H_

#include "llvm/Support/ErrorHandling.h"

#ifdef _MSC_VER
#if LLDB_EVAL_LINKED_AS_SHARED_LIBRARY
#define LLDB_EVAL_API __declspec(dllimport)
#elif LLDB_EVAL_CREATE_SHARED_LIBRARY
#define LLDB_EVAL_API __declspec(dllexport)
#endif
#elif __GNUC__ >= 4 || defined(__clang__)
#define LLDB_EVAL_API __attribute__((visibility("default")))
#endif

#ifndef LLDB_EVAL_API
#define LLDB_EVAL_API
#endif

namespace lldb_eval {

[[noreturn]] inline void unreachable(const char* msg) {
  // llvm_unreachable may ignore "msg" depending on the available platform
  // features. Reference the parameter explicitly to avoid the warning.
  (void)msg;
  llvm_unreachable(msg);
}

}  // namespace lldb_eval

#endif  // LLDB_EVAL_DEFINES_H_
