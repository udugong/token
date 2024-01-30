package jwtcore

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// An Option configures a TokenManager.
type Option[T jwt.Claims, PT Claims[T]] interface {
	apply(*TokenManager[T, PT])
}

// optionFunc wraps a func, so it satisfies the Option interface.
type optionFunc[T jwt.Claims, PT Claims[T]] func(*TokenManager[T, PT])

func (f optionFunc[T, PT]) apply(manager *TokenManager[T, PT]) {
	f(manager)
}

// WithDecryptKey 设置解密密钥.
func WithDecryptKey[T jwt.Claims, PT Claims[T]](key string) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.DecryptKey = key
	})
}

// WithMethod 设置 jwt 的签名方式.
func WithMethod[T jwt.Claims, PT Claims[T]](method jwt.SigningMethod) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.Method = method
	})
}

// WithTimeFunc 设置生成 jwt 的时间函数.
// 可以固定生成 jwt 的时间.
func WithTimeFunc[T jwt.Claims, PT Claims[T]](fn func() time.Time) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.timeFunc = fn
	})
}

// WithSetParserOption 设置 jwt 解析器的选项.
func WithSetParserOption[T jwt.Claims, PT Claims[T]](opts []jwt.ParserOption) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.parserOptions = opts
	})
}

// WithAddParserOption 添加 jwt 解析器的选项.
func WithAddParserOption[T jwt.Claims, PT Claims[T]](opts ...jwt.ParserOption) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.parserOptions = append(t.parserOptions, opts...)
	})
}

// WithIssuer 设置签发者.
func WithIssuer[T jwt.Claims, PT Claims[T]](issuer string) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.Issuer = issuer
	})
}

// WithGenSubjectFunc 设置生成 jwt Subject 的函数.
func WithGenSubjectFunc[T jwt.Claims, PT Claims[T]](fn func() string) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.ClaimsOption.genSubjectFn = fn
	})
}

// WithGenAudienceFunc 设置生成 jwt Audience 的函数.
func WithGenAudienceFunc[T jwt.Claims, PT Claims[T]](fn func() jwt.ClaimStrings) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.ClaimsOption.genAudienceFn = fn
	})
}

// WithGenNotBeforeFunc 设置生成 jwt NotBefore 的函数.
func WithGenNotBeforeFunc[T jwt.Claims, PT Claims[T]](fn func() time.Time) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.ClaimsOption.genNotBeforeFn = fn
	})
}

// WithGenIDFunc 设置生成 jwt ID 的函数.
func WithGenIDFunc[T jwt.Claims, PT Claims[T]](fn func() string) Option[T, PT] {
	return optionFunc[T, PT](func(t *TokenManager[T, PT]) {
		t.genIDFn = fn
	})
}
