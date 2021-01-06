# JWT
Json web token(JWT)提供了一种用于发布接入令牌（Access Token)，并对发布的签名接入令牌进行验证的方法。 令牌（Token）本身包含了一系列声明，应用程序可以根据这些声明限制用户对资源的访问。

## 构成
- header

  + 声明类型，这里是jwt
  + 声明加密的算法 通常直接使用 HMAC SHA256
  > {
    'typ': 'JWT',
    'alg': 'HS256'
  }  

- payload: 载荷就是存放有效信息

  + 标准中注册的声明
    * iss: jwt签发者
    * sub: jwt所面向的用户
    * aud: 接收jwt的一方
    * exp: jwt的过期时间，这个过期时间必须要大于签发时间
    * nbf: 定义在什么时间之前，该jwt都是不可用的.
    * iat: jwt的签发时间
    * jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。

  + 公共的声明: 公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密.

  + 私有的声明: 提供者和消费者所共同定义的声明

- signature: 签名实际上是一个加密的过程，生成一段标识（也是JWT的一部分）作为接收方验证信息是否被篡改的依据。
  > signature = HMACSHA256( base64UrlEncode(header) + '.' + base64UrlEncode(payload), 'secret');

### JWT整体构成
> jwt = HMACSHA256( base64UrlEncode(header) + '.' + base64UrlEncode(payload) + '.'+ signature

## 签名算法
JWT签名算法中，一般有两个选择，HS256和RS256。
- HS256: 使用密钥生成固定的签名，简单地说，HS256 必须与任何想要验证 JWT的 客户端或 API 共享密钥，因此必须注意确保密钥不被泄露。
- RS256: 生成非对称签名，这意味着必须使用私钥来签签名 JWT，并且必须使用对应的公钥来验证签名。与对称算法不同，使用 RS256 可以保证服务端是 JWT 的签名者，因为服务端是唯一拥有私钥的一方。这样做将不再需要在许多应用程序之间共享私钥。