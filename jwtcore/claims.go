package jwtcore

import "github.com/golang-jwt/jwt/v5"

// Claims represent any form of a JWT Claims Set according to
// https://datatracker.ietf.org/doc/html/rfc7519#section-4. In order to have a
// common basis for validation, it is required that an implementation is able to
// supply at least the claim names provided in
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 namely `exp`,
// `iat`, `nbf`, `iss`, `sub` and `aud`.
type Claims[T jwt.Claims] interface {
	jwt.Claims

	SetIssuer(issuer string)
	SetSubject(subject string)
	SetAudience(audience jwt.ClaimStrings)
	SetExpiresAt(expiresAt *jwt.NumericDate)
	SetNotBefore(notBefore *jwt.NumericDate)
	SetIssuedAt(issuedAt *jwt.NumericDate)
	SetID(id string)
	*T
}
