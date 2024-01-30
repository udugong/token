package jwtcore

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/udugong/token"
)

type MyClaims struct {
	Uid int64 `json:"uid,omitempty"`
	RegisteredClaims
}

func TestNewTokenManager(t *testing.T) {
	var genIDFn func() string
	var timeFn func() time.Time
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name          string
		expire        time.Duration
		encryptionKey string
		want          *TokenManager[T, PT]
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name:          "normal",
			expire:        defaultExpire,
			encryptionKey: encryptionKey,
			want: &TokenManager[MyClaims, *MyClaims]{
				Expire:        defaultExpire,
				EncryptionKey: encryptionKey,
				DecryptKey:    encryptionKey,
				Method:        jwt.SigningMethodHS256,
				timeFunc:      timeFn,
				parserOptions: []jwt.ParserOption{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTokenManager[MyClaims, *MyClaims](tt.encryptionKey, tt.expire)
			got.genIDFn = genIDFn
			got.timeFunc = timeFn
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTokenManager_GenerateToken(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name    string
		clm     T
		fn      func() []Option[T, PT]
		want    string
		wantErr error
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "normal",
			clm:  defaultClaims,
			fn: func() []Option[MyClaims, *MyClaims] {
				return []Option[MyClaims, *MyClaims]{
					WithTimeFunc[MyClaims, *MyClaims](
						func() time.Time { return nowTime },
					),
				}
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImV4cCI6MTY5NTU3MTgwMCwiaWF0IjoxNjk1NTcxMjAwfQ.B9sIBtCtX5kp8pk0fjpcy-8HVa991qU5L5nles7Nblw",
			wantErr: nil,
		},
		{
			name: "set_gen_subject_func",
			clm:  defaultClaims,
			fn: func() []Option[MyClaims, *MyClaims] {
				return []Option[MyClaims, *MyClaims]{
					WithTimeFunc[MyClaims, *MyClaims](
						func() time.Time { return nowTime },
					),
					WithGenSubjectFunc[MyClaims, *MyClaims](
						func() string { return "subject" },
					),
				}
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsInN1YiI6InN1YmplY3QiLCJleHAiOjE2OTU1NzE4MDAsImlhdCI6MTY5NTU3MTIwMH0.X_nVbA0yBwFUuRY9OwKVK5_febPG-Z1eldaDLQdUcmU",
			wantErr: nil,
		},
		{
			name: "set_gen_audience_func",
			clm:  defaultClaims,
			fn: func() []Option[MyClaims, *MyClaims] {
				return []Option[MyClaims, *MyClaims]{
					WithTimeFunc[MyClaims, *MyClaims](
						func() time.Time { return nowTime },
					),
					WithGenAudienceFunc[MyClaims, *MyClaims](
						func() jwt.ClaimStrings { return jwt.ClaimStrings{"1"} },
					),
				}
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImF1ZCI6WyIxIl0sImV4cCI6MTY5NTU3MTgwMCwiaWF0IjoxNjk1NTcxMjAwfQ.TLySOq0wXstGyU8BbxYpbuyoKxznZpwl5uWl_20cTy0",
			wantErr: nil,
		},
		{
			name: "set_gen_not_before_func",
			clm:  defaultClaims,
			fn: func() []Option[MyClaims, *MyClaims] {
				return []Option[MyClaims, *MyClaims]{
					WithTimeFunc[MyClaims, *MyClaims](
						func() time.Time { return nowTime },
					),
					WithGenNotBeforeFunc[MyClaims, *MyClaims](
						func() time.Time { return nowTime },
					),
				}
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImV4cCI6MTY5NTU3MTgwMCwibmJmIjoxNjk1NTcxMjAwLCJpYXQiOjE2OTU1NzEyMDB9.z5dQUSK5-BcfZwXnMkFLq_RXD_gyJqXiuhD1EAN-yk4",
			wantErr: nil,
		},
		{
			name: "set_gen_id_func",
			clm:  defaultClaims,
			fn: func() []Option[MyClaims, *MyClaims] {
				return []Option[MyClaims, *MyClaims]{
					WithTimeFunc[MyClaims, *MyClaims](
						func() time.Time { return nowTime },
					),
					WithGenIDFunc[MyClaims, *MyClaims](
						func() string { return "1" },
					),
				}
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImV4cCI6MTY5NTU3MTgwMCwiaWF0IjoxNjk1NTcxMjAwLCJqdGkiOiIxIn0.UNcccX5aSIV3Dqfyi2_jtd8K7_BmCn907Zt2jAw1OgI",
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()...)
			got, err := m.GenerateToken(tt.clm)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTokenManager_VerifyToken(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name    string
		m       token.Manager[T]
		token   string
		want    T
		wantErr error
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name:    "normal",
			m:       defaultManager,
			token:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImV4cCI6MTY5NTU3MTgwMCwiaWF0IjoxNjk1NTcxMjAwfQ.B9sIBtCtX5kp8pk0fjpcy-8HVa991qU5L5nles7Nblw",
			want:    defaultClaims,
			wantErr: nil,
		},
		{
			// token 过期了
			name: "token_expired",
			m: NewTokenManager[MyClaims, *MyClaims](encryptionKey, defaultExpire,
				WithTimeFunc[MyClaims, *MyClaims](func() time.Time {
					return time.UnixMilli(1695671200000)
				}),
			),
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImV4cCI6MTY5NTU3MTgwMCwiaWF0IjoxNjk1NTcxMjAwfQ.B9sIBtCtX5kp8pk0fjpcy-8HVa991qU5L5nles7Nblw",
			wantErr: fmt.Errorf("验证失败: %v",
				fmt.Errorf("%v: %v", jwt.ErrTokenInvalidClaims, jwt.ErrTokenExpired)),
		},
		{
			// token 签名错误
			name:  "bad_sign_key",
			m:     defaultManager,
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEsImV4cCI6MTY5NTU3MTgwMCwiaWF0IjoxNjk1NTcxMjAwfQ.jnzq7EJftxHk82jxl645w875Z0C8yn9WG3uGKhQuLm4",
			wantErr: fmt.Errorf("验证失败: %v",
				fmt.Errorf("%v: %v", jwt.ErrTokenSignatureInvalid, jwt.ErrSignatureInvalid)),
		},
		{
			// 错误的 token
			name:  "bad_token",
			m:     defaultManager,
			token: "bad_token",
			wantErr: fmt.Errorf("验证失败: %v: token contains an invalid number of segments",
				jwt.ErrTokenMalformed),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.VerifyToken(tt.token)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

var (
	encryptionKey = "sign key"
	nowTime       = time.UnixMilli(1695571200000)
	defaultExpire = 10 * time.Minute
	defaultClaims = MyClaims{
		Uid: 1,
		RegisteredClaims: RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(nowTime.Add(defaultExpire)),
			IssuedAt:  jwt.NewNumericDate(nowTime),
		},
	}
	defaultManager = NewTokenManager[MyClaims, *MyClaims](
		encryptionKey, defaultExpire,
		WithTimeFunc[MyClaims, *MyClaims](func() time.Time {
			return nowTime
		}),
		WithAddParserOption[MyClaims, *MyClaims](jwt.WithTimeFunc(
			func() time.Time {
				return nowTime
			},
		)),
	)
)
