package jwtcore

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestWithDecryptKey(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name string
		fn   func() Option[T, PT]
		want string
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "normal",
			fn:   withNop[MyClaims, *MyClaims],
			want: encryptionKey,
		},
		{
			name: "set_another_key",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithDecryptKey[MyClaims, *MyClaims]("another sign key")
			},
			want: "another sign key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).DecryptKey
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithMethod(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name string
		fn   func() Option[T, PT]
		want jwt.SigningMethod
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "normal",
			fn:   withNop[MyClaims, *MyClaims],
			want: jwt.SigningMethodHS256,
		},
		{
			name: "set_another_method",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithMethod[MyClaims, *MyClaims](jwt.SigningMethodHS384)
			},
			want: jwt.SigningMethodHS384,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).Method
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithTimeFunc(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name string
		fn   func() Option[T, PT]
		want int64
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "set_default_time_func",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithTimeFunc[MyClaims, *MyClaims](func() time.Time {
					return nowTime
				})
			},
			want: 1695571200000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).timeFunc().UnixMilli()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithSetParserOption(t *testing.T) {
	fn := jwt.WithTimeFunc(func() time.Time {
		return nowTime
	})
	opts := []jwt.ParserOption{fn}
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name string
		fn   func() Option[T, PT]
		want int
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "normal",
			fn:   withNop[MyClaims, *MyClaims],
			want: 0,
		},
		{
			name: "set_another_parser_option",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithSetParserOption[MyClaims, *MyClaims](opts)
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).parserOptions)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithAddParserOption(t *testing.T) {
	fn := jwt.WithTimeFunc(func() time.Time {
		return nowTime
	})
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name string
		fn   func() Option[T, PT]
		want int
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "normal",
			fn:   withNop[MyClaims, *MyClaims],
			want: 0,
		},
		{
			name: "add_parser_option",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithAddParserOption[MyClaims, *MyClaims](
					fn,
				)
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).parserOptions)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithIssuer(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name string
		fn   func() Option[T, PT]
		want string
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "normal",
			fn:   withNop[MyClaims, *MyClaims],
			want: "",
		},
		{
			name: "set_another_issuer",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithIssuer[MyClaims, *MyClaims]("foo")
			},
			want: "foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).Issuer
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWithGenSubjectFunc(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name    string
		fn      func() Option[T, PT]
		want    string
		wantNil bool
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name:    "normal",
			fn:      withNop[MyClaims, *MyClaims],
			wantNil: true,
		},
		{
			name: "set_another_subject_func",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithGenSubjectFunc[MyClaims, *MyClaims](
					func() string {
						return "1"
					},
				)
			},
			want: "1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genSubjectFn := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).genSubjectFn
			if genSubjectFn != nil {
				assert.Equal(t, tt.want, genSubjectFn())
				return
			}
			if tt.wantNil == true {
				assert.Nil(t, genSubjectFn)
			}
		})
	}
}

func TestWithGenAudienceFunc(t *testing.T) {
	fn := jwt.ClaimStrings{"1"}
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name    string
		fn      func() Option[T, PT]
		want    jwt.ClaimStrings
		wantNil bool
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name:    "normal",
			fn:      withNop[MyClaims, *MyClaims],
			wantNil: true,
		},
		{
			name: "set_gen_audience_func",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithGenAudienceFunc[MyClaims, *MyClaims](
					func() jwt.ClaimStrings {
						return fn
					})
			},
			want:    fn,
			wantNil: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genAudienceFn := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).genAudienceFn
			if genAudienceFn != nil {
				assert.Equal(t, tt.want, genAudienceFn())
				return
			}
			if tt.wantNil == true {
				assert.Nil(t, genAudienceFn)
			}
		})
	}
}

func TestWithGenNotBeforeFunc(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name    string
		fn      func() Option[T, PT]
		want    time.Time
		wantNil bool
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name:    "normal",
			fn:      withNop[MyClaims, *MyClaims],
			wantNil: true,
		},
		{
			name: "set_gen_not_before_func",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithGenNotBeforeFunc[MyClaims, *MyClaims](func() time.Time {
					return nowTime
				})
			},
			want: nowTime,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genNotBeforeFn := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).genNotBeforeFn
			if genNotBeforeFn != nil {
				assert.Equal(t, tt.want, genNotBeforeFn())
				return
			}
			if tt.wantNil == true {
				assert.Nil(t, genNotBeforeFn)
			}
		})
	}
}

func TestWithGenIDFunc(t *testing.T) {
	type testCase[T jwt.Claims, PT Claims[T]] struct {
		name    string
		fn      func() Option[T, PT]
		want    string
		wantNil bool
	}
	tests := []testCase[MyClaims, *MyClaims]{
		{
			name: "normal",
			fn:   withNop[MyClaims, *MyClaims],
			want: "",
		},
		{
			name: "set_another_gen_id_func",
			fn: func() Option[MyClaims, *MyClaims] {
				return WithGenIDFunc[MyClaims, *MyClaims](func() string {
					return "unique id"
				})
			},
			want: "unique id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genIDFn := NewTokenManager[MyClaims, *MyClaims](
				encryptionKey, defaultExpire, tt.fn()).genIDFn
			if genIDFn != nil {
				assert.Equal(t, tt.want, genIDFn())
				return
			}
			if tt.wantNil == true {
				assert.Nil(t, genIDFn)
			}
		})
	}
}

func withNop[T jwt.Claims, PT Claims[T]]() Option[T, PT] {
	return optionFunc[T, PT](func(m *TokenManager[T, PT]) {})
}
