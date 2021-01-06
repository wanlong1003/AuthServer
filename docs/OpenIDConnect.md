# OpenID Connect(OIDC)
OpenID Connect是基于OAuth 2.0规范族的可互操作的身份验证协议。

> Authentication + OAuth2.0 = OpenID Connect

- OpenID = Authentication
- OAuth = Authorization

## 核心
OAuth2提供了Access Token来解决授权第三方客户端访问受保护资源的问题；OIDC在这个基础上提供了ID Token来解决第三方客户端标识用户身份认证的问题。OIDC的核心在于在OAuth2的授权流程中，一并提供用户的身份认证信息（ID Token）给到第三方客户端，ID Token使用JWT格式来包装，得益于JWT（JSON Web Token）的自包含性，紧凑性以及防篡改机制，使得ID Token可以安全的传递给第三方客户端程序并且容易被验证。此外还提供了UserInfo的接口，用户获取用户的更完整的信息。

## 流程
```
+----------+                                   +----------+
|          |                                   |          |
|          |---------(1) AuthN Request-------->|          |
|          |                                   |          |
|          |  +--------+                       |          |
|          |  |        |                       |          |
|          |  |  End-  |<--(2) AuthN & AuthZ-->|          |
|          |  |  User  |                       |  OpenID  |
|  Client  |  |        |                       | Provider |
|          |  +--------+                       |          |
|          |                                   |          |
|          |<--------(3) AuthN Response--------|          |
|          |                                   |          |
|          |---------(4) UserInfo Request----->|          |
|          |                                   |          |
|          |<--------(5) UserInfo Response-----|          |
|          |                                   |          |
+----------+                                   +----------+
```
- AuthN=Authentication，表示认证
- AuthZ=Authorization，代表授权

## ID Token
OIDC对OAuth2最主要的扩展就是提供了ID Token。ID Token是一个安全令牌，是一个授权服务器提供的包含用户信息（由一组Cliams构成以及其他辅助的Cliams）的JWT格式的数据结构。ID Token的主要构成部分如下（使用OAuth2流程的OIDC）。

- iss = Issuer Identifier：必须。提供认证信息者的唯一标识。一般是一个https的url（不包含querystring和fragment部分）。
- sub = Subject Identifier：必须。iss提供的EU的标识，在iss范围内唯一。它会被RP用来标识唯一的用户。最长为255个ASCII个字符。
- aud = Audience(s)：必须。标识ID Token的受众。必须包含OAuth2的client_id。
- exp = Expiration time：必须。过期时间，超过此时间的ID Token会作废不再被验证通过。
- iat = Issued At Time：必须。JWT的构建的时间。
- auth_time = AuthenticationTime：EU完成认证的时间。如果RP发送AuthN请求的时候携带max_age的参数，则此Claim是必须的。
- nonce：RP发送请求的时候提供的随机字符串，用来减缓重放攻击，也可以来关联ID Token和RP本身的Session信息。
- acr = Authentication Context Class Reference：可选。表示一个认证上下文引用值，可以用来标识认证上下文类。
- amr = Authentication Methods References：可选。表示一组认证方法。
- azp = Authorized party：可选。结合aud使用。只有在被认证的一方和受众（aud）不一致时才使用此值，一般情况下很少使用。

## 授权类型
OIDC的认证流程主要是由OAuth2的几种授权流程延伸而来的，有以下3种：

### Authorization Code：使用OAuth2的授权码来换取Id Token和Access Token。
使用OAuth2的Authorization Code的方式来完成用户身份认证，所有的Token都是通过Token EndPoint来发放的。
#### Authentication Request
* 参数
  - scope：必须。OIDC的请求必须包含值为“openid”的scope的参数。
  - response_type：必选。同OAuth2。
  - client_id：必选。同OAuth2。
  - redirect_uri：必选。同OAuth2。
  - state：推荐。同OAuth2。防止CSRF, XSRF。
  以上这5个参数是和OAuth2相同的。
  - response_mode：可选。OIDC新定义的参数（OAuth 2.0 Form Post Response Mode），用来指定Authorization Endpoint以何种方式返回数据。
  - nonce：可选。ID Token中的出现的nonce就是来源于此。
  - display ： 可选。指示授权服务器呈现怎样的界面给EU。有效值有（page，popup，touch，wap），其中默认是page。page=普通的页面，popup=弹出框，touch=支持触控的页面，wap=移动端页面。
  - prompt：可选。这个参数允许传递多个值，使用空格分隔。用来指示授权服务器是否引导EU重新认证和同意授权。有效值有（none，login，consent，select_account）。
    + none=不实现现任何认证和确认同意授权的页面，如果没有认证授权过，则返回错误login_required或interaction_required。
    + login=重新引导EU进行身份认证，即使已经登录。
    + consent=重新引导EU确认同意授权。
    + select_account=假如EU在授权服务器有多个账号的话，允许EU选择一个账号进行认证。
  - max_age：可选。代表EU认证信息的有效时间，对应ID Token中auth_time的claim。比如设定是20分钟，则超过了时间，则需要引导EU重新认证。
  - ui_locales：可选。用户界面的本地化语言设置项。
  - id_token_hint：可选。之前发放的ID Token，如果ID Token经过验证且是有效的，则需要返回一个正常的响应；如果有误，则返回对应的错误提示。
  - login_hint：可选。向授权服务器提示登录标识符，EU可能会使用它登录(如果需要的话)。比如指定使用用户使用blackheart账号登录，当然EU也可以使用其他账号登录，这只是类似html中input元素的placeholder。
  - acr_values：可选。Authentication Context Class Reference values，对应ID Token中的acr的Claim。此参数允许多个值出现，使用空格分割。

> GET /authorize?  
>     response_type=code  
>     &scope=openid%20profile%20email  
>     &client_id=s6BhdRkqt3  
>     &state=af0ifjsldkj  
>     &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb HTTP/1.1  
> 
>   Host: server.example.com  

#### Authentication Response
> HTTP/1.1 302 Found  
> Location: https://client.example.org/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=af0ifjsldkj

#### Request ID Token
> HTTP/1.1 200 OK  
> Content-Type: application/json  
> Cache-Control: no-store  
> Pragma: no-cache  
>   
> {  
>     "access_token": "SlAV32hkKG",  
>     "token_type": "Bearer",  
>     "refresh_token": "8xLOxBtZp8",  
>     "expires_in": 3600,  
>     "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg"  
> }

### Implicit：使用OAuth2的Implicit流程获取Id Token和Access Token。
Implicit Flow的工作方式是在OAuth2 Implicit Flow上附加提供id_token

### Hybrid：混合Authorization Code + Implici。
> Hybrid Flow = Authorization Code Flow+Implicit Flow    

id_token和授权码通过浏览器传递，access_token则是通过后端获取。

## UserInfo Endpoint
UserIndo EndPoint是一个受OAuth2保护的资源。在Client得到Access Token后可以请求此资源，然后获得一组EU相关的Claims，这些信息可以说是ID Token的扩展，比如如果你觉得ID Token中只需包含EU的唯一标识sub即可（避免ID Token过于庞大），然后通过此接口获取完整的EU的信息。

### Request
> GET /userinfo HTTP/1.1  
> Host: server.example.com  
> Authorization: Bearer SlAV32hkKG  

### Response
> HTTP/1.1 200 OK  
> Content-Type: application/json  
>    
> {  
>     "sub": "248289761001",  
>     "name": "Jane Doe",  
>     "given_name": "Jane",  
>     "family_name": "Doe",  
>     "preferred_username": "j.doe",  
>     "email": "janedoe@example.com",  
>     "picture": "http://example.com/janedoe/me.jpg"  
> }  

其中sub代表EU的唯一标识，这个claim是必须的，其他的都是可选的。

## 参考
- https://openid.net/specs/openid-connect-core-1_0.html
- https://www.cnblogs.com/linianhui/p/openid-connect-core.html