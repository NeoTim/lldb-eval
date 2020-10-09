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

#ifndef LLDB_EVAL_PARSER_H_
#define LLDB_EVAL_PARSER_H_

#include <memory>
#include <string>

#include "clang/Basic/FileManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/HeaderSearch.h"
#include "clang/Lex/LiteralSupport.h"
#include "clang/Lex/ModuleLoader.h"
#include "clang/Lex/Preprocessor.h"
#include "lldb-eval/ast.h"
#include "lldb-eval/expression_context.h"

namespace lldb_eval {

inline std::string TokenKindsJoin(clang::tok::TokenKind k) {
  std::string s = clang::tok::getTokenName(k);
  return "'" + s + "'";
}

template <typename... Ts>
inline std::string TokenKindsJoin(clang::tok::TokenKind k, Ts... ks) {
  return TokenKindsJoin(k) + ", " + TokenKindsJoin(ks...);
}

// Pure recursive descent parser for C++ like expressions.
// EBNF grammar is described here:
// docs/expr-ebnf.txt
class Parser {
 public:
  // Type for representing errors that can occur during the parsing of the
  // expression.
  // TODO(werat): Use std::string + std::error_code?
  // TODO(werat): This should at least contain the position in the expression.
  using Error = std::string;

 public:
  explicit Parser(ExpressionContext& expr_ctx);

  ExprResult Run();

  bool HasError() { return !error_.empty(); }
  const Error& GetError() { return error_; }

 private:
  ExprResult ParseExpression();
  ExprResult ParseAssignmentExpression();
  ExprResult ParseConditionalExpression();
  ExprResult ParseLogicalOrExpression();
  ExprResult ParseLogicalAndExpression();
  ExprResult ParseInclusiveOrExpression();
  ExprResult ParseExclusiveOrExpression();
  ExprResult ParseAndExpression();
  ExprResult ParseEqualityExpression();
  ExprResult ParseRelationalExpression();
  ExprResult ParseShiftExpression();
  ExprResult ParseAdditiveExpression();
  ExprResult ParseMultiplicativeExpression();
  ExprResult ParseCastExpression();
  ExprResult ParseUnaryExpression();
  ExprResult ParsePostfixExpression();
  ExprResult ParsePrimaryExpression();

  TypeDeclaration ParseTypeId();
  void ParseTypeSpecifierSeq(TypeDeclaration* type_decl);
  bool ParseTypeSpecifier(TypeDeclaration* type_decl);
  std::string ParseNestedNameSpecifier();
  std::string ParseTypeName();

  std::string ParseTemplateArgumentList();
  std::string ParseTemplateArgument();

  void ParsePtrOperator(TypeDeclaration* type_decl);

  bool ResolveTypeFromTypeDecl(const TypeDeclaration& type_decl);

  bool IsSimpleTypeSpecifierKeyword(clang::Token token) const;
  bool IsCvQualifier(clang::Token token) const;
  bool IsPtrOperator(clang::Token token) const;

  IdExpression ParseIdExpression();
  std::string ParseUnqualifiedId();

  ExprResult ParseNumericLiteral();
  ExprResult ParseBooleanLiteral();

  ExprResult ParseNumericConstant(clang::Token token);
  ExprResult ParseFloatingLiteral(clang::NumericLiteralParser& literal,
                                  clang::Token token);
  ExprResult ParseIntegerLiteral(clang::NumericLiteralParser& literal,
                                 clang::Token token);

  void ConsumeToken();
  void BailOut(const std::string& error, clang::SourceLocation loc);

  void Expect(clang::tok::TokenKind kind) {
    if (token_.isNot(kind)) {
      BailOut("expected " + TokenKindsJoin(kind) +
                  ", got: " + TokenDescription(token_),
              token_.getLocation());
    }
  }

  template <typename... Ts>
  void ExpectOneOf(clang::tok::TokenKind k, Ts... ks) {
    if (!token_.isOneOf(k, ks...)) {
      BailOut("expected any of (" + TokenKindsJoin(k, ks...) +
                  "), got: " + TokenDescription(token_),
              token_.getLocation());
    }
  }

  std::string TokenDescription(const clang::Token& token) {
    auto spelling = pp_->getSpelling(token);
    auto kind_name = token.getName();
    return "<'" + spelling + "' (" + kind_name + ")>";
  }

 private:
  friend class TentativeParsingAction;

  // Parser doesn't own expression context. The produced AST may depend on it
  // (for example, for source locations), so it's expected that expression
  // context will outlive the parser.
  ExpressionContext* expr_ctx_;

  // The token lexer is stopped at (aka "current token").
  clang::Token token_;
  // Holds an error if it occures during parsing.
  Error error_;

  std::unique_ptr<clang::TargetInfo> ti_;
  std::unique_ptr<clang::LangOptions> lang_opts_;
  std::unique_ptr<clang::HeaderSearch> hs_;
  std::unique_ptr<clang::TrivialModuleLoader> tml_;
  std::unique_ptr<clang::Preprocessor> pp_;
};

// Enables tentative parsing mode, allowing to rollback the parser state. Call
// Commit() or Rollback() to control the parser state. If neither was called,
// the destructor will assert.
class TentativeParsingAction {
 public:
  TentativeParsingAction(Parser* parser) : parser_(parser) {
    backtrack_token_ = parser_->token_;
    parser_->pp_->EnableBacktrackAtThisPos();
    enabled_ = true;
  }

  ~TentativeParsingAction() {
    assert(!enabled_ &&
           "Tentative parsing wasn't finalized. Did you forget to call "
           "Commit() or Rollback()?");
  }

  void Commit() {
    parser_->pp_->CommitBacktrackedTokens();
    enabled_ = false;
  }
  void Rollback() {
    parser_->pp_->Backtrack();
    parser_->error_.clear();
    parser_->token_ = backtrack_token_;
    enabled_ = false;
  }

 private:
  Parser* parser_;
  clang::Token backtrack_token_;
  bool enabled_;
};

}  // namespace lldb_eval

#endif  // LLDB_EVAL_PARSER_H_
