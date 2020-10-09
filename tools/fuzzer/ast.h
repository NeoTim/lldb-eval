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

#ifndef INCLUDE_AST_H
#define INCLUDE_AST_H

#include <cinttypes>
#include <memory>
#include <ostream>
#include <string>
#include <variant>

namespace fuzzer {

enum class ScalarType : unsigned char;
class TaggedType;
class PointerType;
class ReferenceType;

using QualifiableType = std::variant<ScalarType, TaggedType, PointerType>;
std::ostream& operator<<(std::ostream& os, const QualifiableType& type);

// Important: We _must_ specify an underlying type. Otherwise, from C++17
// onward, casting to an invalid value of an enum type with no underlying type
// is undefined behavior.
enum class CvQualifiers : unsigned char {
  // Not an actual flag, intended to help with checking if a type has any
  // cv-qualifiers.
  None = 0,
  Const = 1 << 0,
  Volatile = 1 << 1,
};

constexpr CvQualifiers operator|(CvQualifiers lhs, CvQualifiers rhs) {
  return (CvQualifiers)((unsigned char)lhs | ((unsigned char)rhs));
}

constexpr CvQualifiers operator&(CvQualifiers lhs, CvQualifiers rhs) {
  return (CvQualifiers)((unsigned char)lhs & ((unsigned char)rhs));
}

constexpr CvQualifiers& operator&=(CvQualifiers& lhs, CvQualifiers rhs) {
  lhs = lhs & rhs;
  return lhs;
}

constexpr CvQualifiers& operator|=(CvQualifiers& lhs, CvQualifiers rhs) {
  lhs = lhs | rhs;
  return lhs;
}
std::ostream& operator<<(std::ostream& os, CvQualifiers qualifiers);

enum class ScalarType : unsigned char {
  EnumMin,
  Void = EnumMin,
  Bool,
  // Have `char` explicitly because it is implementation dependent whether
  // `char` maps to `signed char` or `unsigned char`.
  Char,
  SignedChar,
  UnsignedChar,
  SignedShort,
  UnsignedShort,
  SignedInt,
  UnsignedInt,
  SignedLong,
  UnsignedLong,
  SignedLongLong,
  UnsignedLongLong,
  EnumMax = UnsignedLongLong,
};
constexpr size_t NUM_SCALAR_TYPES = (size_t)ScalarType::EnumMax + 1;
std::ostream& operator<<(std::ostream& os, ScalarType type);

class TaggedType {
 public:
  explicit TaggedType(std::string name);

  const std::string& name() const;

  friend std::ostream& operator<<(std::ostream& os, const TaggedType& type);

 private:
  std::string name_;
};

class QualifiedType {
 public:
  explicit QualifiedType(QualifiableType type,
                         CvQualifiers cv_qualifiers = CvQualifiers::None);

  const QualifiableType& type() const;
  CvQualifiers cv_qualifiers() const;

  friend std::ostream& operator<<(std::ostream& os, const QualifiedType& type);

 private:
  std::unique_ptr<QualifiableType> type_;
  CvQualifiers cv_qualifiers_;
};

class PointerType {
 public:
  explicit PointerType(QualifiedType type);

  const QualifiedType& type() const;

  friend std::ostream& operator<<(std::ostream& os, const PointerType& type);

 private:
  QualifiedType type_;
};

class ReferenceType {
 public:
  explicit ReferenceType(QualifiedType type);

  const QualifiedType& type() const;

  friend std::ostream& operator<<(std::ostream& os, const ReferenceType& type);

 private:
  QualifiedType type_;
};

using Type = std::variant<QualifiedType, ReferenceType>;
std::ostream& operator<<(std::ostream& os, const Type& type);

class BinaryExpr;
class UnaryExpr;
class VariableExpr;
class IntegerConstant;
class DoubleConstant;
class ParenthesizedExpr;
class AddressOf;
class MemberOf;
class MemberOfPtr;
class ArrayIndex;
class TernaryExpr;

enum class UnOp : unsigned char {
  // Used to determine the first enum element.
  EnumFirst,
  Plus = EnumFirst,
  Neg,
  LogicalNot,
  BitNot,
  // Used to determine the last enum element.
  EnumLast = BitNot,
};
constexpr size_t NUM_UN_OPS = (size_t)UnOp::EnumLast + 1;

enum class BinOp : unsigned char {
  // Used to determine the first enum element.
  EnumFirst,
  // Arithmetic operators.
  Plus = EnumFirst,
  Minus,
  Mult,
  Div,
  Mod,
  // Logical operators.
  LogicalAnd,
  LogicalOr,
  // Bitwise operators.
  BitAnd,
  BitOr,
  BitXor,
  Shl,
  Shr,
  // Comparison operators.
  Eq,
  Ne,
  Lt,
  Le,
  Gt,
  Ge,
  // Used to determine the last enum element.
  EnumLast = Ge,
};
constexpr size_t NUM_BIN_OPS = (size_t)BinOp::EnumLast + 1;

using Expr =
    std::variant<IntegerConstant, DoubleConstant, VariableExpr, UnaryExpr,
                 BinaryExpr, AddressOf, MemberOf, MemberOfPtr, ArrayIndex,
                 TernaryExpr, ParenthesizedExpr>;
constexpr size_t NUM_EXPR_KINDS = std::variant_size_v<Expr>;

std::ostream& operator<<(std::ostream& os, const Expr& expr);

class BinaryExpr {
 public:
  BinaryExpr(Expr lhs, BinOp op, Expr rhs);

  const Expr& lhs() const;
  const Expr& rhs() const;
  BinOp op() const;
  int precedence() const;

  friend std::ostream& operator<<(std::ostream& os, const BinaryExpr& expr);

 private:
  std::unique_ptr<Expr> lhs_;
  std::unique_ptr<Expr> rhs_;
  BinOp op_;
};

class UnaryExpr {
 public:
  static constexpr int PRECEDENCE = 3;

  UnaryExpr(UnOp op, Expr expr);

  UnOp op() const;
  const Expr& expr() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const UnaryExpr& expr);

 private:
  std::unique_ptr<Expr> expr_;
  UnOp op_;
};

class VariableExpr {
 public:
  static constexpr int PRECEDENCE = 0;

  explicit VariableExpr(std::string name);

  const std::string& name() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const VariableExpr& expr);

 private:
  std::string name_;
};

class IntegerConstant {
 public:
  static constexpr int PRECEDENCE = 0;

  explicit IntegerConstant(uint64_t value);

  uint64_t value() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os,
                                  const IntegerConstant& expr);

 private:
  uint64_t value_;
};

class DoubleConstant {
 public:
  static constexpr int PRECEDENCE = 0;

  explicit DoubleConstant(double value);

  double value() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const DoubleConstant& expr);

 private:
  double value_;
};

class ParenthesizedExpr {
 public:
  static constexpr int PRECEDENCE = 0;

  explicit ParenthesizedExpr(Expr expr);

  const Expr& expr() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os,
                                  const ParenthesizedExpr& expr);

 private:
  std::unique_ptr<Expr> expr_;
};

class AddressOf {
 public:
  static constexpr int PRECEDENCE = 3;

  explicit AddressOf(Expr expr);

  const Expr& expr() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const AddressOf& expr);

 private:
  std::unique_ptr<Expr> expr_;
};

class MemberOf {
 public:
  static constexpr int PRECEDENCE = 2;

  MemberOf(Expr expr, std::string field);

  const Expr& expr() const;
  const std::string& field() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const MemberOf& expr);

 private:
  std::unique_ptr<Expr> expr_;
  std::string field_;
};

class MemberOfPtr {
 public:
  static constexpr int PRECEDENCE = 2;

  MemberOfPtr(Expr expr, std::string field);

  const Expr& expr() const;
  const std::string& field() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const MemberOfPtr& expr);

 private:
  std::unique_ptr<Expr> expr_;
  std::string field_;
};

class ArrayIndex {
 public:
  static constexpr int PRECEDENCE = 2;

  ArrayIndex(Expr expr, Expr idx);

  const Expr& expr() const;
  const Expr& idx() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const ArrayIndex& expr);

 private:
  std::unique_ptr<Expr> expr_;
  std::unique_ptr<Expr> idx_;
};

class TernaryExpr {
 public:
  static constexpr int PRECEDENCE = 16;

  TernaryExpr(Expr cond, Expr lhs, Expr rhs);

  const Expr& cond() const;
  const Expr& lhs() const;
  const Expr& rhs() const;
  int precedence() const { return PRECEDENCE; }

  friend std::ostream& operator<<(std::ostream& os, const TernaryExpr& expr);

 private:
  std::unique_ptr<Expr> cond_;
  std::unique_ptr<Expr> lhs_;
  std::unique_ptr<Expr> rhs_;
};

void dump_expr(const Expr& expr);

int bin_op_precedence(BinOp op);

}  // namespace fuzzer

#endif  // INCLUDE_AST_H
