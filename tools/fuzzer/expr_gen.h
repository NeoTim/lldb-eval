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

#ifndef INCLUDE_EXPR_GEN_H
#define INCLUDE_EXPR_GEN_H

#include <array>
#include <cstdint>
#include <random>

#include "tools/fuzzer/ast.h"

namespace fuzzer {

constexpr float PROB_PARENTHESIZE = 0.5f;
constexpr float PROB_CONST = 0.3f;
constexpr float PROB_VOLATILE = 0.3f;

enum class ExprKind : unsigned char {
  IntegerConstant,
  DoubleConstant,
  VariableExpr,
  UnaryExpr,
  BinaryExpr,
  AddressOf,
  MemberOf,
  MemberOfPtr,
  ArrayIndex,
  TernaryExpr,
  EnumLast = TernaryExpr,
};
constexpr size_t NUM_GEN_EXPR_KINDS = (size_t)ExprKind::EnumLast + 1;

enum class TypeKind : unsigned char {
  ScalarType,
  TaggedType,
  PointerType,
  ReferenceType,
  EnumLast = ReferenceType,
};
constexpr size_t NUM_GEN_TYPE_KINDS = (size_t)TypeKind::EnumLast + 1;

class Weights {
 private:
  std::array<float, NUM_GEN_EXPR_KINDS> expr_weights_;
  std::array<float, NUM_GEN_TYPE_KINDS> type_weights_;

  using expr_iterator = decltype(expr_weights_)::iterator;
  using expr_const_iterator = decltype(expr_weights_)::const_iterator;

  using type_iterator = decltype(type_weights_)::iterator;
  using type_const_iterator = decltype(type_weights_)::const_iterator;

 public:
  expr_iterator expr_begin() { return expr_weights_.begin(); }
  expr_iterator expr_end() { return expr_weights_.end(); }

  expr_const_iterator expr_begin() const { return expr_weights_.begin(); }
  expr_const_iterator expr_end() const { return expr_weights_.end(); }

  type_iterator type_begin() { return type_weights_.begin(); }
  type_iterator type_end() { return type_weights_.end(); }

  type_const_iterator type_begin() const { return type_weights_.begin(); }
  type_const_iterator type_end() const { return type_weights_.end(); }

  float& operator[](ExprKind kind) { return expr_weights_[(size_t)kind]; }
  float& operator[](TypeKind kind) { return type_weights_[(size_t)kind]; }

  const float& operator[](ExprKind kind) const {
    return expr_weights_[(size_t)kind];
  }
  const float& operator[](TypeKind kind) const {
    return type_weights_[(size_t)kind];
  }
};

class GeneratorRng {
 public:
  virtual ~GeneratorRng() {}

  virtual BinOp gen_bin_op() = 0;
  virtual UnOp gen_un_op() = 0;
  virtual ExprKind gen_expr_kind(const Weights& array) = 0;
  virtual TypeKind gen_type_kind(const Weights& array) = 0;
  virtual uint64_t gen_u64(uint64_t min, uint64_t max) = 0;
  virtual double gen_double(double min, double max) = 0;
  virtual bool gen_parenthesize(float probability = PROB_PARENTHESIZE) = 0;
  virtual CvQualifiers gen_cv_qualifiers(
      float const_prob = PROB_CONST, float volatile_prob = PROB_VOLATILE) = 0;
};

class DefaultGeneratorRng : public GeneratorRng {
 public:
  explicit DefaultGeneratorRng(uint32_t seed) : rng_(seed) {}

  BinOp gen_bin_op() override;
  UnOp gen_un_op() override;
  ExprKind gen_expr_kind(const Weights& array) override;
  TypeKind gen_type_kind(const Weights& array) override;
  uint64_t gen_u64(uint64_t min, uint64_t max) override;
  double gen_double(double min, double max) override;
  bool gen_parenthesize(float probability = PROB_PARENTHESIZE) override;
  CvQualifiers gen_cv_qualifiers(float const_prob = PROB_CONST,
                                 float volatile_prob = PROB_VOLATILE) override;

 private:
  std::mt19937 rng_;
};

class ExprGenerator {
 public:
  explicit ExprGenerator(std::unique_ptr<GeneratorRng> rng)
      : rng_(std::move(rng)) {}

  Expr generate();

 private:
  static constexpr uint64_t MAX_INT_VALUE = 10;
  static constexpr double MAX_DOUBLE_VALUE = 10.0;

  static constexpr char VAR[] = "x";

  Expr maybe_parenthesized(Expr expr);

  IntegerConstant gen_integer_constant(const Weights&);
  DoubleConstant gen_double_constant(const Weights&);
  VariableExpr gen_variable_expr(const Weights&);
  BinaryExpr gen_binary_expr(const Weights&);
  UnaryExpr gen_unary_expr(const Weights&);

  Expr gen_with_weights(const Weights&);

 private:
  std::unique_ptr<GeneratorRng> rng_;
};

}  // namespace fuzzer

#endif  // INCLUDE_EXPR_GEN_H
