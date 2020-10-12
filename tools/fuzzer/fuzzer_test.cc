#include <algorithm>
#include <cassert>
#include <sstream>
#include <type_traits>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tools/fuzzer/ast.h"
#include "tools/fuzzer/expr_gen.h"

using namespace fuzzer;
using namespace testing;

namespace fuzzer {

void PrintTo(const Expr& expr, std::ostream* os) { *os << "`" << expr << "`"; }

}  // namespace fuzzer

class FakeGeneratorRng : public GeneratorRng {
 public:
  FakeGeneratorRng() {}

  BinOp gen_bin_op() override {
    assert(!bin_ops_.empty());
    BinOp op = bin_ops_.back();
    bin_ops_.pop_back();

    return op;
  }

  UnOp gen_un_op() override {
    assert(!un_ops_.empty());
    UnOp op = un_ops_.back();
    un_ops_.pop_back();

    return op;
  }

  ExprKind gen_expr_kind(const Weights&) override {
    assert(!expr_kinds_.empty());
    ExprKind kind = expr_kinds_.back();
    expr_kinds_.pop_back();

    return kind;
  }

  TypeKind gen_type_kind(const Weights&) override {
    assert(!type_kinds_.empty());
    TypeKind kind = type_kinds_.back();
    type_kinds_.pop_back();

    return kind;
  }

  uint64_t gen_u64(uint64_t, uint64_t) override {
    assert(!u64_constants_.empty());
    uint64_t constant = u64_constants_.back();
    u64_constants_.pop_back();

    return constant;
  }

  double gen_double(double, double) override {
    assert(!double_constants_.empty());
    double constant = double_constants_.back();
    double_constants_.pop_back();

    return constant;
  }

  CvQualifiers gen_cv_qualifiers(float, float) override {
    assert(!cv_qualifiers_.empty());
    CvQualifiers cv = cv_qualifiers_.back();
    cv_qualifiers_.pop_back();

    return cv;
  }

  bool gen_parenthesize(float) override { return false; }

  static FakeGeneratorRng from_expr(const Expr& expr) {
    FakeGeneratorRng rng;
    std::visit(rng, expr);

    std::reverse(rng.un_ops_.begin(), rng.un_ops_.end());
    std::reverse(rng.bin_ops_.begin(), rng.bin_ops_.end());
    std::reverse(rng.u64_constants_.begin(), rng.u64_constants_.end());
    std::reverse(rng.double_constants_.begin(), rng.double_constants_.end());
    std::reverse(rng.expr_kinds_.begin(), rng.expr_kinds_.end());
    std::reverse(rng.cv_qualifiers_.begin(), rng.cv_qualifiers_.end());

    return rng;
  }

  void operator()(const UnaryExpr& e) {
    expr_kinds_.push_back(ExprKind::UnaryExpr);
    un_ops_.push_back(e.op());
    std::visit(*this, e.expr());
  }

  void operator()(const BinaryExpr& e) {
    expr_kinds_.push_back(ExprKind::BinaryExpr);
    bin_ops_.push_back(e.op());
    std::visit(*this, e.lhs());
    std::visit(*this, e.rhs());
  }

  void operator()(const VariableExpr&) {
    expr_kinds_.push_back(ExprKind::VariableExpr);
  }

  void operator()(const IntegerConstant& e) {
    expr_kinds_.push_back(ExprKind::IntegerConstant);
    u64_constants_.push_back(e.value());
  }

  void operator()(const DoubleConstant& e) {
    expr_kinds_.push_back(ExprKind::DoubleConstant);
    double_constants_.push_back(e.value());
  }

  void operator()(const ParenthesizedExpr& e) { std::visit(*this, e.expr()); }

  void operator()(const AddressOf& e) {
    expr_kinds_.push_back(ExprKind::AddressOf);
    std::visit(*this, e.expr());
  }

  void operator()(const MemberOf& e) {
    expr_kinds_.push_back(ExprKind::MemberOf);
    std::visit(*this, e.expr());
  }

  void operator()(const MemberOfPtr& e) {
    expr_kinds_.push_back(ExprKind::MemberOfPtr);
    std::visit(*this, e.expr());
  }

  void operator()(const ArrayIndex& e) {
    expr_kinds_.push_back(ExprKind::ArrayIndex);
    std::visit(*this, e.expr());
    std::visit(*this, e.idx());
  }

  void operator()(const TernaryExpr& e) {
    expr_kinds_.push_back(ExprKind::TernaryExpr);
    std::visit(*this, e.cond());
    std::visit(*this, e.lhs());
    std::visit(*this, e.rhs());
  }

  void operator()(const CastExpr& e) {
    std::visit(*this, e.type());
    std::visit(*this, e.expr());
  }

  void operator()(const QualifiedType& e) {
    cv_qualifiers_.push_back(e.cv_qualifiers());
    std::visit(*this, e.type());
  }

  void operator()(const PointerType& e) {
    type_kinds_.push_back(TypeKind::PointerType);
    (*this)(e.type());
  }

  void operator()(const ReferenceType& e) {
    type_kinds_.push_back(TypeKind::ReferenceType);
    (*this)(e.type());
  }

  void operator()(const TaggedType& e) {
    type_kinds_.push_back(TypeKind::TaggedType);
    tagged_types_.push_back(e.name());
  }

  void operator()(const ScalarType& e) {
    type_kinds_.push_back(TypeKind::ScalarType);
    scalar_types_.push_back(e);
  }

 private:
  std::vector<UnOp> un_ops_;
  std::vector<BinOp> bin_ops_;
  std::vector<uint64_t> u64_constants_;
  std::vector<double> double_constants_;
  std::vector<ExprKind> expr_kinds_;
  std::vector<TypeKind> type_kinds_;
  std::vector<CvQualifiers> cv_qualifiers_;
  std::vector<ScalarType> scalar_types_;
  std::vector<std::string> tagged_types_;
};

struct Mismatch {
  std::string lhs;
  std::string rhs;

  Mismatch(std::string lhs, std::string rhs) : lhs(lhs), rhs(rhs) {}
};

class AstComparator {
 public:
  void operator()(const UnaryExpr& lhs, const UnaryExpr& rhs) {
    if (lhs.op() != rhs.op()) {
      add_mismatch(lhs, rhs);
      return;
    }

    std::visit(*this, lhs.expr(), rhs.expr());
  }

  void operator()(const BinaryExpr& lhs, const BinaryExpr& rhs) {
    if (lhs.op() != rhs.op()) {
      add_mismatch(lhs, rhs);
      return;
    }

    std::visit(*this, lhs.lhs(), rhs.lhs());
    std::visit(*this, lhs.rhs(), rhs.rhs());
  }

  void operator()(const VariableExpr& lhs, const VariableExpr& rhs) {
    if (lhs.name() != rhs.name()) {
      add_mismatch(lhs, rhs);
    }
  }

  void operator()(const IntegerConstant& lhs, const IntegerConstant& rhs) {
    if (lhs.value() != rhs.value()) {
      add_mismatch(lhs, rhs);
    }
  }

  void operator()(const DoubleConstant& lhs, const DoubleConstant& rhs) {
    if (lhs.value() != rhs.value()) {
      add_mismatch(lhs, rhs);
    }
  }

  void operator()(const ParenthesizedExpr& lhs, const ParenthesizedExpr& rhs) {
    std::visit(*this, lhs.expr(), rhs.expr());
  }

  void operator()(const AddressOf& lhs, const AddressOf& rhs) {
    std::visit(*this, lhs.expr(), rhs.expr());
  }

  void operator()(const MemberOf& lhs, const MemberOf& rhs) {
    if (lhs.field() != rhs.field()) {
      add_mismatch(lhs, rhs);
      return;
    }

    std::visit(*this, lhs.expr(), rhs.expr());
  }

  void operator()(const MemberOfPtr& lhs, const MemberOfPtr& rhs) {
    if (lhs.field() != rhs.field()) {
      add_mismatch(lhs, rhs);
      return;
    }

    std::visit(*this, lhs.expr(), rhs.expr());
  }

  void operator()(const ArrayIndex& lhs, const ArrayIndex& rhs) {
    std::visit(*this, lhs.expr(), rhs.expr());
    std::visit(*this, lhs.idx(), rhs.idx());
  }

  void operator()(const TernaryExpr& lhs, const TernaryExpr& rhs) {
    std::visit(*this, lhs.cond(), rhs.cond());
    std::visit(*this, lhs.lhs(), rhs.lhs());
    std::visit(*this, lhs.rhs(), rhs.rhs());
  }

  void operator()(const CastExpr& lhs, const CastExpr& rhs) {
    std::visit(*this, lhs.type(), rhs.type());
    std::visit(*this, lhs.expr(), rhs.expr());
  }

  void operator()(const QualifiedType& lhs, const QualifiedType& rhs) {
    std::visit(*this, lhs.type(), rhs.type());
    if (lhs.cv_qualifiers() != rhs.cv_qualifiers()) {
      add_mismatch(lhs.cv_qualifiers(), rhs.cv_qualifiers());
    }
  }

  void operator()(const ReferenceType& lhs, const ReferenceType& rhs) {
    (*this)(lhs.type(), rhs.type());
  }

  void operator()(const PointerType& lhs, const PointerType& rhs) {
    (*this)(lhs.type(), rhs.type());
  }

  void operator()(const TaggedType& lhs, const TaggedType& rhs) {
    if (lhs.name() != rhs.name()) {
      add_mismatch(lhs.name(), rhs.name());
    }
  }

  void operator()(ScalarType lhs, ScalarType rhs) {
    if (lhs != rhs) {
      add_mismatch(lhs, rhs);
    }
  }

  template <typename T, typename U,
            typename = std::enable_if_t<!std::is_same_v<T, U>>>
  void operator()(const T& lhs, const U& rhs) {
    add_mismatch(lhs, rhs);
  }

  const std::vector<Mismatch>& mismatches() const { return mismatches_; }

 private:
  template <typename T, typename U>
  void add_mismatch(const T& lhs, const U& rhs) {
    std::ostringstream lhs_stream;
    std::ostringstream rhs_stream;

    lhs_stream << lhs;
    rhs_stream << rhs;

    mismatches_.emplace_back(lhs_stream.str(), rhs_stream.str());
  }

 private:
  std::vector<Mismatch> mismatches_;
};

MATCHER_P(MatchesAst, expected,
          (negation ? "does not match AST " : "matches AST ") +
              PrintToString(expected.get())) {
  AstComparator cmp;

  std::visit(cmp, expected.get(), arg);
  const auto& mismatches = cmp.mismatches();
  if (mismatches.empty()) {
    return true;
  }

  *result_listener << "with mismatches occuring as follows:\n";
  for (const auto& e : mismatches) {
    *result_listener << "* Expected: " << PrintToString(e.lhs) << "\n"
                     << "*   Actual: " << PrintToString(e.rhs) << "\n";
  }

  return false;
}

struct PrecedenceTestParam {
  std::string str;
  std::shared_ptr<Expr> expr;

  PrecedenceTestParam(std::string str, Expr expr)
      : str(std::move(str)), expr(std::make_shared<Expr>(std::move(expr))) {}
};

std::ostream& operator<<(std::ostream& os, const PrecedenceTestParam& param) {
  return os << "`" << param.str << "`";
}

class OperatorPrecedence : public TestWithParam<PrecedenceTestParam> {};

TEST_P(OperatorPrecedence, CorrectAst) {
  const auto& param = GetParam();

  auto fake_rng = std::make_unique<FakeGeneratorRng>(
      FakeGeneratorRng::from_expr(*param.expr));

  ExprGenerator gen(std::move(fake_rng));
  auto expr = gen.generate();
  std::ostringstream os;
  os << expr;

  EXPECT_THAT(expr, MatchesAst(std::cref(*param.expr)));
  EXPECT_THAT(os.str(), StrEq(param.str));
}

std::vector<PrecedenceTestParam> gen_precedence_params() {
  std::vector<PrecedenceTestParam> params;
  {
    // clang-format off
    Expr expected = BinaryExpr(
        IntegerConstant(3),
        BinOp::Mult,
        ParenthesizedExpr(
            BinaryExpr(IntegerConstant(4), BinOp::Plus, IntegerConstant(5))));
    // clang-format on

    std::string str = "3 * (4 + 5)";
    params.emplace_back(std::move(str), std::move(expected));
  }
  {
    // clang-format off
    Expr expected = BinaryExpr(
        BinaryExpr(IntegerConstant(3), BinOp::Mult, IntegerConstant(4)),
        BinOp::Plus,
        IntegerConstant(5));
    // clang-format on

    std::string str = "3 * 4 + 5";
    params.emplace_back(std::move(str), std::move(expected));
  }
  {
    // clang-format off
    Expr expected = BinaryExpr(
        BinaryExpr(IntegerConstant(3), BinOp::Minus, IntegerConstant(4)),
        BinOp::Plus,
        IntegerConstant(5));
    // clang-format on

    std::string str = "3 - 4 + 5";
    params.emplace_back(std::move(str), std::move(expected));
  }
  {
    // clang-format off
    Expr expected = BinaryExpr(
        IntegerConstant(3),
        BinOp::Minus,
        ParenthesizedExpr(
            BinaryExpr(IntegerConstant(4), BinOp::Plus, IntegerConstant(5))));
    // clang-format on

    std::string str = "3 - (4 + 5)";
    params.emplace_back(std::move(str), std::move(expected));
  }

  return params;
}

INSTANTIATE_TEST_SUITE_P(Fuzzer, OperatorPrecedence,
                         ValuesIn(gen_precedence_params()));

struct TypePrintTestParam {
  std::string str;
  std::shared_ptr<Type> type;

  explicit TypePrintTestParam(std::string str, Type type)
      : str(std::move(str)), type(std::make_shared<Type>(std::move(type))) {}
};

std::ostream& operator<<(std::ostream& os, const TypePrintTestParam& param) {
  return os << param.str;
}

class TypePrinting : public TestWithParam<TypePrintTestParam> {};

TEST_P(TypePrinting, CorrectStrType) {
  const auto& param = GetParam();

  std::ostringstream os;
  os << *param.type;
  EXPECT_THAT(os.str(), StrEq(param.str));
}

std::vector<TypePrintTestParam> gen_typing_params() {
  std::vector<TypePrintTestParam> params;

  {
    Type type = QualifiedType(ScalarType::SignedInt);
    std::string str = "int";

    params.emplace_back(std::move(str), std::move(type));
  }

  {
    Type type(QualifiedType(PointerType(QualifiedType(
        PointerType(QualifiedType(ScalarType::Char, CvQualifiers::Const))))));
    std::string str = "const char**";

    params.emplace_back(std::move(str), std::move(type));
  }

  {
    Type type(ReferenceType(QualifiedType(
        PointerType(QualifiedType(ScalarType::SignedInt, CvQualifiers::Const)),
        CvQualifiers::Volatile)));
    std::string str = "const int* volatile&";

    params.emplace_back(std::move(str), std::move(type));
  }

  {
    Type type(QualifiedType(PointerType(
        QualifiedType(TaggedType("TestStruct"), CvQualifiers::Const))));
    std::string str = "const TestStruct*";

    params.emplace_back(std::move(str), std::move(type));
  }

  {
    Type type(QualifiedType(
        PointerType(QualifiedType(ScalarType::Void, CvQualifiers::Const))));
    std::string str = "const void*";

    params.emplace_back(std::move(str), std::move(type));
  }

  {
    Type type(QualifiedType(PointerType(QualifiedType(ScalarType::Void)),
                            CvQualifiers::Const));
    std::string str = "void* const";

    params.emplace_back(std::move(str), std::move(type));
  }

  return params;
}

INSTANTIATE_TEST_SUITE_P(Fuzzer, TypePrinting, ValuesIn(gen_typing_params()));
