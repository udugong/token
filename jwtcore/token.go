package jwtcore

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenManager 定义 jwt 的管理程序.
type TokenManager[T jwt.Claims, PT Claims[T]] struct {
	EncryptionKey string             // 加密密钥
	DecryptKey    string             // 解密密钥
	Method        jwt.SigningMethod  // 签名方式
	Expire        time.Duration      // 有效期
	timeFunc      func() time.Time   // 控制生成 jwt 的时间
	parserOptions []jwt.ParserOption // jwt 解析器的选项
	ClaimsOption
}

// ClaimsOption claims 配置.
type ClaimsOption struct {
	Issuer         string                  // 签发人
	genSubjectFn   func() string           // 主体
	genAudienceFn  func() jwt.ClaimStrings // 接收方
	genNotBeforeFn func() time.Time        // 生效时间
	genIDFn        func() string           // 生成 JWT ID (jti) 的函数
}

// NewTokenManager 创建 jwt 管理器.
// Method: 默认使用 jwt.SigningMethodHS256 对称签名方式.
// DecryptKey: 默认与 EncryptionKey 相同.
func NewTokenManager[T jwt.Claims, PT Claims[T]](encryptionKey string,
	expire time.Duration, options ...Option[T, PT]) *TokenManager[T, PT] {
	manager := &TokenManager[T, PT]{
		Expire:        expire,
		EncryptionKey: encryptionKey,
		DecryptKey:    encryptionKey,
		Method:        jwt.SigningMethodHS256,
		timeFunc:      time.Now,
		parserOptions: []jwt.ParserOption{},
	}
	return manager.WithOptions(options...)
}

// GenerateToken 生成一个 jwt token.
func (t *TokenManager[T, PT]) GenerateToken(clm T) (string, error) {
	p := PT(&clm)
	if t.genSubjectFn != nil {
		p.SetSubject(t.genSubjectFn())
	}
	if t.genAudienceFn != nil {
		p.SetAudience(t.genAudienceFn())
	}
	if t.genNotBeforeFn != nil {
		p.SetNotBefore(jwt.NewNumericDate(t.genNotBeforeFn()))
	}
	if t.genIDFn != nil {
		p.SetID(t.genIDFn())
	}
	nowTime := t.timeFunc()
	p.SetIssuer(t.Issuer)
	p.SetIssuedAt(jwt.NewNumericDate(nowTime))
	p.SetExpiresAt(jwt.NewNumericDate(nowTime.Add(t.Expire)))
	return jwt.NewWithClaims(t.Method, clm).
		SignedString([]byte(t.EncryptionKey))
}

// VerifyToken 认证 token 并返回 claims 与 error.
func (t *TokenManager[T, PT]) VerifyToken(token string) (T, error) {
	var zeroClm T
	clm := zeroClm
	var clmPtr any = &clm
	withClaims, err := jwt.ParseWithClaims(token, clmPtr.(jwt.Claims),
		func(*jwt.Token) (interface{}, error) {
			return []byte(t.DecryptKey), nil
		},
		t.parserOptions...,
	)
	if err != nil || !withClaims.Valid {
		return zeroClm, fmt.Errorf("验证失败: %v", err)
	}
	return clm, nil
}

func (t *TokenManager[T, PT]) WithOptions(opts ...Option[T, PT]) *TokenManager[T, PT] {
	c := t.clone()
	for _, opt := range opts {
		opt.apply(c)
	}
	return c
}

func (t *TokenManager[T, PT]) clone() *TokenManager[T, PT] {
	copyHandler := *t
	return &copyHandler
}
