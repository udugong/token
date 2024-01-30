package token

// Manager token 管理接口.
type Manager[T any] interface {
	GenerateToken(T) (string, error)
	VerifyToken(token string) (T, error)
}
