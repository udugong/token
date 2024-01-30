# token

令牌管理

# go version

`>=1.20`

# usage

下载安装：`go get github.com/udugong/token`

- [jwt 的使用](#jwtcore-package)

# `jwtcore` package

该`jwtcore`包提供了生成与校验 `json web token` 的方法，使您可以通过简单的配置快速使用 `jwt`
的生成与校验功能。该功能是基于 [golang-jwt](https://github.com/golang-jwt/jwt) 进行封装的。

- 利用泛型可以自定义 claims 内容
- 生成/校验 token

#### 使用方法

1. 定义 Claims 结构体

   定义 Claims
   需要嵌入 [jwtcore.RegisteredClaims](https://github.com/udugong/token/blob/main/jwtcore/registered_claims.go#L14)
   或者实现 [jwtcore.Claims[T jwt.Claims]](https://github.com/udugong/token/blob/main/jwtcore/claims.go#L11)
   接口，其余成员可以自行定义。

   ```go
   import "github.com/udugong/token/jwtcore"
   
   type Claims struct {
   	Uid int64 `json:"uid"` // 用户ID
   	// Nickname string `json:"nickname"` // 昵称
   
   	// 嵌入
   	jwtcore.RegisteredClaims
   }
   
   ```

2. 创建令牌管理器

   创建令牌管理器需要传两个参数：签名密钥、过期时间，以及确定类型必须设置步骤1的结构体以及其指针。该服务默认使用 `SHA256`
   作为签名方式，因此加密密钥与解密密钥相同。

   ```go
   // 创建令牌管理器
   key := "sign key"
   tokenManager := jwtcore.NewTokenManager[Claims, *Claims](key, 10*time.Minute)
   ```

3. 生成 `jwt`

   ```go
   // 传入 Claims
   token, err := tokenManager.GenerateToken(Claims{Uid: 1})
   if err != nil {
   	panic(err)
   }
   fmt.Println(token)
   ```

4. 校验 `token`

   ```go
   // 校验 token 并解析 claims
   clm, err := tokenManager.VerifyToken(token)
   if err != nil {
   	fmt.Println(err.Error())
   }
   fmt.Printf("%d\n", clm.Uid) // 1
   ```
