#include <asn1/lexer.hpp>

using namespace asn1;
using namespace std::string_view_literals;

// Basic token types
constexpr auto toks1 = lex("Foo ::= SEQUENCE { }");
static_assert(toks1[0].kind == TokenKind::Identifier);
static_assert(toks1[0].text.view() == "Foo");
static_assert(toks1[1].kind == TokenKind::Assignment);
static_assert(toks1[2].kind == TokenKind::KwSequence);
static_assert(toks1[3].kind == TokenKind::LBrace);
static_assert(toks1[4].kind == TokenKind::RBrace);
static_assert(toks1[5].kind == TokenKind::Eof);

// Multi-word keywords
constexpr auto toks2 = lex("BIT STRING");
static_assert(toks2[0].kind == TokenKind::KwBitString);
static_assert(toks2[0].text.view() == "BIT STRING");

constexpr auto toks3 = lex("OCTET STRING");
static_assert(toks3[0].kind == TokenKind::KwOctetString);

constexpr auto toks4 = lex("OBJECT IDENTIFIER");
static_assert(toks4[0].kind == TokenKind::KwObjectIdentifier);

// Comments
constexpr auto toks5 = lex("INTEGER -- a comment\nBOOLEAN");
static_assert(toks5[0].kind == TokenKind::KwInteger);
static_assert(toks5[1].kind == TokenKind::KwBoolean);
static_assert(toks5[2].kind == TokenKind::Eof);

// Numbers
constexpr auto toks6 = lex("42");
static_assert(toks6[0].kind == TokenKind::Number);
static_assert(toks6[0].text.view() == "42");

// Tags
constexpr auto toks7 = lex("[0] EXPLICIT");
static_assert(toks7[0].kind == TokenKind::LBracket);
static_assert(toks7[1].kind == TokenKind::Number);
static_assert(toks7[1].text.view() == "0");
static_assert(toks7[2].kind == TokenKind::RBracket);
static_assert(toks7[3].kind == TokenKind::KwExplicit);

// OPTIONAL, DEFAULT
constexpr auto toks8 = lex("OPTIONAL DEFAULT");
static_assert(toks8[0].kind == TokenKind::KwOptional);
static_assert(toks8[1].kind == TokenKind::KwDefault);

// Module header keywords
constexpr auto toks9 = lex("DEFINITIONS IMPLICIT TAGS ::= BEGIN END");
static_assert(toks9[0].kind == TokenKind::KwDefinitions);
static_assert(toks9[1].kind == TokenKind::KwImplicit);
static_assert(toks9[2].kind == TokenKind::KwTags);
static_assert(toks9[3].kind == TokenKind::Assignment);
static_assert(toks9[4].kind == TokenKind::KwBegin);
static_assert(toks9[5].kind == TokenKind::KwEnd);

// DotDot
constexpr auto toks10 = lex("(0..MAX)");
static_assert(toks10[0].kind == TokenKind::LParen);
static_assert(toks10[1].kind == TokenKind::Number);
static_assert(toks10[2].kind == TokenKind::DotDot);
static_assert(toks10[3].kind == TokenKind::Identifier); // MAX
static_assert(toks10[4].kind == TokenKind::RParen);

// Hyphenated identifiers
constexpr auto toks11 = lex("id-ecPublicKey");
static_assert(toks11[0].kind == TokenKind::Identifier);
static_assert(toks11[0].text.view() == "id-ecPublicKey");

// IMPORTS ... FROM ... ;
constexpr auto toks12 = lex("IMPORTS Foo, Bar FROM Baz;");
static_assert(toks12[0].kind == TokenKind::KwImports);
static_assert(toks12[1].kind == TokenKind::Identifier);
static_assert(toks12[2].kind == TokenKind::Comma);
static_assert(toks12[3].kind == TokenKind::Identifier);
static_assert(toks12[4].kind == TokenKind::KwFrom);
static_assert(toks12[5].kind == TokenKind::Identifier);
static_assert(toks12[6].kind == TokenKind::Semicolon);

int main() {
    return 0;
}
