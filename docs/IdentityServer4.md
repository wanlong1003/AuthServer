# IdentityServer4
IdentityServer4是一个用于ASP.Net Core的OpenID Connect和OAuth 2.0框架。

## 功能特性
- 保护你的资源
- 使用本地帐户或通过外部身份提供程序对用户进行身份验证
- 提供会话管理和单点登录
- 管理和验证客户机
- 向客户发出标识和访问令牌
- 验证令牌

### IdentityServer4 功能特性
- Authentication as a Service： 可以为你的应用（如网站、本地应用、移动端、服务）做集中式的登录逻辑和工作流控制。IdentityServer是完全实现了OpenID Connect协议标准
- Single Sign-on / Sign-out： 在多个应用程序类型上进行单点登录(和单点退出)。
- Access Control for APIs： 为不同类型的客户端，例如服务器到服务器、web应用程序、SPAs和本地/移动应用程序，发出api的访问令牌。
- Federation Gateway： 支持来自Azure Active Directory, Google, Facebook这些知名应用的身份认证，可以不必关心连接到这些应用的细节就可以保护你的应用。
- Focus on Customization： 最重要的是identityserver可以根据需求自行开发来适应应用程序的变化。identityserver不是一个框架、也不是一个盒装产品或一个saas系统，您可以编写代码来适应各种场景。

## 术语
- 身份认证服务器（IdentityServer）:向客户端发送安全令牌（security token）
- 用户（User）: 用户是使用已注册的客户端访问资源的人
- 客户端（Client）: 客户端就是从identityserver请求令牌的软件
- 资源（Resources）: 资源就是你想用identityserver保护的东西，每一个资源都有一个唯一的名称，客户端使用这个唯一的名称来确定想访问哪一个资源
- 身份令牌（Id Token）: 是一个安全令牌，包含用户信息、认证时间和认证方式。身份令牌可以包含额外的身份数据。
  + iss = Issuer Identifier：必须。提供认证信息者的唯一标识。一般是一个https的url（不包含querystring和fragment部分）。
  + sub = Subject Identifier：必须。iss提供的EU的标识，在iss范围内唯一。它会被RP用来标识唯一的用户。最长为255个ASCII个字符。
  + aud = Audience(s)：必须。标识ID Token的受众。必须包含OAuth2的client_id。
  + exp = Expiration time：必须。过期时间，超过此时间的ID Token会作废不再被验证通过。
  + iat = Issued At Time：必须。JWT的构建的时间。
  + auth_time = AuthenticationTime：EU完成认证的时间。如果RP发送AuthN请求的时候携带max_age的参数，则此Claim是必须的。
  + nonce = string：RP发送请求的时候提供的随机字符串，用来减缓重放攻击，也可以来关联ID Token和RP本身的Session信息。
  + acr = Authentication Context Class Reference：可选。表示一个认证上下文引用值，可以用来标识认证上下文类。
  + amr = Authentication Methods References：可选。表示一组认证方法。
  + azp = Authorized party：可选。结合aud使用。只有在被认证的一方和受众（aud）不一致时才使用此值，一般情况下很少使用。
- 访问令牌（Access Token）: 访问令牌允许客户端访问某个 API 资源。客户端请求到访问令牌，然后使用这个令牌来访问 API资源。
- 刷新令牌（Refresh Token）: 当Access Token过期后，可以通过Refresh Token重新获取Access Token



## 测试服务端搭建
1. 创建netcore web项目
> dotnet new web

2. 添加包IdentityServer4
> dotnet add package IdentityServer4

3. 配置IdentityServer4
``` c#
//Startup.ConfigureServices 中配置IdentityServer4服务
// 添加下面代码后可以使Token中的Claim的Key变为简单的单词
// System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
services.AddIdentityServer()
    .AddDeveloperSigningCredential()
    //添加测试Identity资源
    .AddInMemoryIdentityResources(new IdentityResource[] {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResources.Email(),
        new IdentityResources.Address()
    })
    //添加api资源
    .AddInMemoryApiResources(new ApiResource[] {
        new ApiResource("api1"){ Scopes = { "api1_scope" } },
        new ApiResource("api2"){ Scopes = { "api2_scope" } }
    })
    .AddInMemoryApiScopes(new ApiScope[]{
        new ApiScope("api1_scope"),
        new ApiScope("api2_scope")
    })
    //添加客户端
    .AddInMemoryClients(new Client[]{
        new Client(){
            ClientId = "client",
            ClientName = "client credentials 客户端",
            ClientSecrets = { new Secret("123456".Sha256())},
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AllowedScopes = { "api1", StandardScopes.OpenId,  StandardScopes.Address, StandardScopes.Profile }
        }
    })
    //添加测试用户
    .AddTestUsers(new List<TestUser>(){
        new TestUser(){
            SubjectId = "1",
            Username="admin",
            Password = "123456",
            Claims = {
                new Claim("email", "wanlong@163.com"),
                new Claim("address","西安"),
            }
        }
    });

//Startup.Configure() 中添加IdentityServer4中间件
app.UseIdentityServer();
```

4. 启动服务
``` bash
dotnet run --urls=http://*:5000
```

5. 查看发现文档
浏览器访问 http://localhost:5000/.well-known/openid-configuration 即可获取到发现文档，内容如下
``` json
{
    "issuer": "http://localhost:5000",
    "jwks_uri": "http://localhost:5000/.well-known/openid-configuration/jwks",
    "authorization_endpoint": "http://localhost:5000/connect/authorize",     //授权码终结点
    "token_endpoint": "http://localhost:5000/connect/token",                 //token终结点
    "userinfo_endpoint": "http://localhost:5000/connect/userinfo",           //用户信息终结点
    "end_session_endpoint": "http://localhost:5000/connect/endsession",
    "check_session_iframe": "http://localhost:5000/connect/checksession",
    "revocation_endpoint": "http://localhost:5000/connect/revocation",
    "introspection_endpoint": "http://localhost:5000/connect/introspect",
    "device_authorization_endpoint": "http://localhost:5000/connect/deviceauthorization",
    "frontchannel_logout_supported": true,
    "frontchannel_logout_session_supported": true,
    "backchannel_logout_supported": true,
    "backchannel_logout_session_supported": true,
    //scopes取值范围
    "scopes_supported": [
        "openid",
        "profile",
        "email",
        "address",
        "api1",
        "offline_access"
    ],
    //claim取值范围
    "claims_supported": [
        "sub",
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "email",
        "email_verified",
        "address"
    ],
    //grant_types取值范围
    "grant_types_supported": [
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "implicit",
        "password",
        "urn:ietf:params:oauth:grant-type:device_code"
    ],
    //response_type 取值范围
    "response_types_supported": [
        "code",
        "token",
        "id_token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
    ],
    "response_modes_supported": [
        "form_post",
        "query",
        "fragment"
    ],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "subject_types_supported": [
        "public"
    ],
    "code_challenge_methods_supported": [
        "plain",
        "S256"
    ],
    "request_parameter_supported": true
}
```

## 测试api
1. 创建一个api项目
> dotnet new api

2. 添加包Microsoft.AspNetCore.Authentication.JwtBearer
> dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer

3. 创建api
``` C#
// Controllers
[Route("api/[controller]")]
[ApiController]
[Authorize]
public class IdentityController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return new JsonResult(User.Claims.Select(c=> new { c.Type, c.Value }));
    }
}

[Route("api/[controller]")]
[ApiController]
[Authorize(policy: "api1")]
public class Api1Controller : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return new JsonResult(User.Claims.Select(c=> new { c.Type, c.Value }));
    }
}
```

4. 配置认证访问并添加认证中间件
``` c#
//Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllers();
    services.AddAuthentication("Bearer")
        .AddJwtBearer("Bearer", options =>
        {
            options.Authority = "http://localhost:5000";
            options.RequireHttpsMetadata = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false
            };
        });

    services.AddAuthorization(options =>
    {
        options.AddPolicy("api1", policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireClaim("scope", "api1");
        });
    });
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseAuthentication();
    app.UseRouting();            
    app.UseAuthorization();
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
        // 全局添加Policy
        //.RequireAuthorization("api1");
    });
}
```

5. 启动服务
> dotnet run --urls=http://*:5001

6. 测试
访问 http://localhost:5001/api/identity 返回状态吗401

## 授权模式

### 客户端模式（client credentials）
主要用于程序间的对接，无用户参与的场景。

#### 使用Postman
  ![](resource/identityserver4_client_credentials.png)

  结果
  ``` json
  {
    "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkU4MkI3RDkyOUZGNjUwM0M1MUQzREU3RkI0NjA4RDZCIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MDE2MTIxNjcsImV4cCI6MTYwMTYxNTc2NywiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDAwIiwiY2xpZW50X2lkIjoiY2xpZW50IiwianRpIjoiNzA0QjIzQjM0RTcxODdERDYxNTVDREI5QUI2NjA1NUQiLCJpYXQiOjE2MDE2MTIxNjcsInNjb3BlIjpbImFwaTEiXX0.dM23xxL_E8XJOVV1KCLzdeRsBk5tOsFQVvVOCCFQEjUOEb6jhvw7vuyaxLQqDatoimAwKv5jT_AxFzUg7QUxkMLGKbvu-EcvFurKQ7YYXfVIZBbhyZ3vWYH8OecZ5myHuvqumSJlxMC7tvzEYgJluYKUHYXpVIfEMjhyQuhOSzWqfW7NdR-uXqC98rgp96DgpLv25v-VLF3iVMJFseU1Or-ZLYzhgFg3iqjT-rKkS9LoqxqGCo8VSq4aA5JEgp0eoja6TPVNv7rL9OrCMcsnYqwBSVUoePJScdGy1SJsh_y76x5zQu0JuWy-xTQ4aRl9YcnfwAwfW7v9RvRI4F1w3A",
    "expires_in": 3600,
    "token_type": "Bearer",
    "scope": "api1"
  }
  ```

  访问 http://localhost:5001/api/identity 时添加http头Authorization即可正常访问接口
  ``` 
  Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkU4MkI3RDkyOUZGNjUwM0M1MUQzREU3RkI0NjA4RDZCIiwidHlwIjoiYXQrand0In0.  eyJuYmYiOjE2MDE2MTIxNjcsImV4cCI6MTYwMTYxNTc2NywiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDAwIiwiY2xpZW50X2lkIjoiY2xpZW50IiwianRpIjoiNzA0QjIzQjM0RTcxODdERDYxNTVDREI5QUI2NjA1NUQiLCJpYXQiOjE2MDE2MTI  xNjcsInNjb3BlIjpbImFwaTEiXX0.  dM23xxL_E8XJOVV1KCLzdeRsBk5tOsFQVvVOCCFQEjUOEb6jhvw7vuyaxLQqDatoimAwKv5jT_AxFzUg7QUxkMLGKbvu-EcvFurKQ7YYXfVIZBbhyZ3vWYH8OecZ5myHuvqumSJlxMC7tvzEYgJluYKUHYXpVIfEMjhyQuhOSzWqfW7NdR-uXqC98rg  p96DgpLv25v-VLF3iVMJFseU1Or-ZLYzhgFg3iqjT-rKkS9LoqxqGCo8VSq4aA5JEgp0eoja6TPVNv7rL9OrCMcsnYqwBSVUoePJScdGy1SJsh_y76x5zQu0JuWy-xTQ4aRl9YcnfwAwfW7v9RvRI4F1w3A
  ```

#### 使用 Code
1. 创建控制台程序
> dotnet new console

2. 添加包IdentityModel
> dotnet add package IdentityModel

3. 测试代码
``` c#
static async Task Main(string[] args)
{
    var client = new HttpClient();
    //获取发现文档
    var disco = await client.GetDiscoveryDocumentAsync("http://localhost:5000");
    if (disco.IsError)
    {
        Console.WriteLine(disco.Error);
    }
    else
    {
        //请求Token
        var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "client",
            ClientSecret = "123456",
            Scope = "api1"
        });
        if (tokenResponse.IsError)
        {
            Console.WriteLine(tokenResponse.Error);
        }
        else
        {
            Console.WriteLine(tokenResponse.Json);
            //使用Token请求api
            var apiClient = new HttpClient();
            apiClient.SetBearerToken(tokenResponse.AccessToken);
            var response = await apiClient.GetAsync("http://localhost:5001/api/identity");
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(response.StatusCode);
            }
            else
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine(content);
            }
        }
    }
    Console.ReadLine();
}
```

### 密码模式（resource owner password credentials）
适用于桌面程序或APP，用户直接在客户端中输入用户凭据，并由客户端程序发往服务器。所以鉴权服务器与资源服务器必须相互信任，比如同一个团队开发的APP和CS客户端。

#### 服务端添加密码模式的client
``` c#
new Client(){
    ClientId = "password",
    ClientName = "resource owner password credentials 客户端",
    ClientSecrets = { new Secret("123456".Sha256())},
    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
    AllowedScopes = { "api1" }
}
```

#### 使用 Postman
![](resource/identityserver4_password.png)

结果：
``` json
{
    "access_token":   "eyJhbGciOiJSUzI1NiIsImtpZCI6IkU4MkI3RDkyOUZGNjUwM0M1MUQzREU3RkI0NjA4RDZCIiwidHlwIjo  iYXQrand0In0.  eyJuYmYiOjE2MDE2MTUwNjEsImV4cCI6MTYwMTYxODY2MSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDAw  IiwiY2xpZW50X2lkIjoicGFzc3dvcmQiLCJzdWIiOiIxIiwiYXV0aF90aW1lIjoxNjAxNjE1MDYxLCJpZHAi  OiJsb2NhbCIsImp0aSI6IjZFQTIyNkMxMTlFMDUyN0VEMTkyNEI4MjEwMzY2MzNEIiwiaWF0IjoxNjAxNjE1  MDYxLCJzY29wZSI6WyJhcGkxIl0sImFtciI6WyJwd2QiXX0.  ZZwvhxFtiaduvNDMrZPAc4ZntKU_rSEKrgJPlSg_RCEC7i68pii4sErmSME_h3MR2TdM_k5ZW6I6opARg2WD  X0ZpDyNBvEDbL9qNnQl87T_OOvBpMyvRegMgm0zj1KnWR-ulrgJx_gSCOF9-rgnXLYQxiaFlhzC3Iw33RHoi  tCE4FZ13fZ7G3A61PvmRS57Qqu_Aa0lfMWfntOnqjl9DKpVLgbDqzQku-rREEYIrMLifgpjrJGSwrl3ISgcu  TpPOf1qBzaoh38F3MvPpx1C7LIzSqBzKYiV3-_0xGXJBNq2VOkJdirUZgfeDoMHIYygt3ou77SVPSoMg-Hw0  EaC3Ug",
    "expires_in": 3600,
    "token_type": "Bearer",
    "scope": "api1"
}
```
使用结果中的access_token即可正常访问http://localhost:5001/api/identity

#### 使用 Code
1. 创建控制台程序
> dotnet new console

2. 添加包IdentityModel
> dotnet add package IdentityModel

3. 测试代码
``` c#
static async Task Main(string[] args)
{
    var client = new HttpClient();
    //获取发现文档
    var disco = await client.GetDiscoveryDocumentAsync("http://localhost:5000");
    if (disco.IsError)
    {
        Console.WriteLine(disco.Error);
    }
    else
    {
        //请求Token
        var tokenResponse = await client.RequestPasswordTokenAsync(new   PasswordTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "password",
            ClientSecret = "123456",
            UserName = "admin",
            Password = "123456",
            Scope = "api1"
        });
        if (tokenResponse.IsError)
        {
            Console.WriteLine(tokenResponse.Error);
        }
        else
        {
            Console.WriteLine(tokenResponse.Json);
            //使用Token请求api
            var apiClient = new HttpClient();
            apiClient.SetBearerToken(tokenResponse.AccessToken);
            var response = await apiClient.GetAsync("http://localhost:5001/api/  identity");
            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(response.StatusCode);
            }
            else
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine(content);
            }
        }
    }
    Console.ReadLine();
}
```

### 授权码模式（authorization code）
授权码模式需要从定向到授权服务器，然后用户在页面上进行登录和授权，在用户授权完成后通过浏览器转发“授权码”给客户端，客户端后端使用授权码从授权服务器取得token。

#### 服务器端
1. 添加测试客户端
``` c#
new Client
{
    ClientId = "mvc",
    ClientName = "授权码客户端",
    ClientSecrets = { new Secret("123456".Sha256()) },
    AllowedGrantTypes = GrantTypes.Code,
    RedirectUris = { "http://localhost:5002/signin-oidc" },
    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },
    AllowOfflineAccess = true,  //启用刷新token
    AlwaysIncludeUserClaimsInIdToken = true,  //Token中是否包含用户Claim信息
    RequireConsent = true,  //是否需要用户同意，单点登录设置为false
    AllowedScopes = new List<string> { StandardScopes.OpenId, StandardScopes.Profile, "api1" }
}

```
2. 服务端添加登录和授权ui
> dotnet new is4ui
注意：需要先安装 IdentityServer4.Templates
> dotnet new -i IdentityServer4.Templates

3. 配置mvc相关的代码（省略代码）

#### 客户端
1. 创建一个mvc客户端
> dotnet new mvc

2. 安装包 Microsoft.AspNetCore.Authentication.OpenIdConnect
> dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect

3. 配置认证访问
``` c#
services.AddAuthentication(options =>
    {
        options.DefaultScheme = "Cookies";
        options.DefaultChallengeScheme = "oidc";
    })
    .AddCookie("Cookies")
    .AddOpenIdConnect("oidc", options =>
    {
        options.Authority = "http://localhost:5000";
        options.ClientId = "mvc";
        options.ClientSecret = "123456";
        options.ResponseType = "code";
        options.SaveTokens = true;
        options.RequireHttpsMetadata = false;

        //将claim信息存储到token中
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        //options.Scope.Add("address");
        //options.Scope.Add("email");
        //options.Scope.Add("api1");
        //options.Scope.Add("offline_access");  //刷新Token
        //options.GetClaimsFromUserInfoEndpoint = true;
        //options.ClaimAction 集合中存储了token中要被过滤掉的Claim
        //options.ClaimAction.Remove("exp");
        //options.ClaimAction.DeleteClaim("sid");
    });
```

4. 添加中间件并启用全局授权
``` c#
app.UseStaticFiles();
app.UseAuthentication();
app.UseRouting();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .RequireAuthorization(); //或者在action上添加[Authorize]
});
```

5. 测试
  - 访问 http://localhost:5002
  - 浏览器重定向到授权服务器的 http://localhost:5000/connect/authorize
  - 授权服务器未登录，需要重定向到登录页面 http://localhost:5000/Account/Login
  - 输入用户名和密码，验证通过后重定向到 http://localhost:5000/connect/authorize/callback
  - 然后重定向到 http://localhost:5002/signin-oidc 并携带上一步中取得的授权码
  - 服务端通过授权码取得access_token并写入Cookie中
  - 登录完成，重定向到http://localhost:5002

6. 注销
``` c#
public IActionResult Logout()
{
    return SignOut("Cookies", "oidc");
}
```
注意：该方式不仅会清除本地还会重定向到服务端并清除服务端的Cookie

这里登出后页面停留再identityserver上，如果想自动跳回到客户端需要修改文件：Quickstart.AccountOptions
```
public static bool AutomaticRedirectAfterSignOut = true;
```

7. 刷新Token
``` c#
var client = new HttpClient();
var disco = await client.GetDiscoveryDocumentAsync("http://localhost:5000");

var refreshToke = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
var tokenResponse = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
    {
        ClientId = "client",
        ClientSecret = "123456",
        Scope = "api1",
        GrantType=OpenIdConnectGrantTypes.RefreshToken,
        RefreshToken = refreshToke
    });
```

#### 访问受保护的API
通过下面的方法可以取得Token, 然后再调用对应的api即可。
``` c#
AccessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
IdToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.IdToken);
Code = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.Code);
RefreshToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);

Claims = HttpContext.User.Claims;
```

### 简化模式（implicit）
授权码模式的简化，授权完成后直接带回来access_token，简化了“授权码”的步骤。一般用于单页面应用，比如Vue站点。  
> 由于令牌直接传给前端，不是很安全，用于一些安全性要求不高的场景。建议把token时效性设置短一些。不支持 refresh token。

客户端库： oids-client.js

1. 测试客户端
``` c#
new Client
{
    ClientId = "implicit",
    ClientName = "Implicit客户端",
    ClientUri = "http://127.0.0.1:5500", 
    AllowedGrantTypes = GrantTypes.Implicit,
    AllowAccessTokensViaBrowser = true,  //是否通过浏览器返回access_token
    RequireConsent = true,  //是否需要用户同意
    AccessTokenLifetime = 300,  //access_token有效期
    RedirectUris =
    {
        "http://127.0.0.1:5500/implicit/callback.html", //登录完成回调地址
    },
    PostLogoutRedirectUris =
    {
        "http://127.0.0.1:5500/implicit/index.html"  //退出登录回调地址
    },
    AllowedCorsOrigins =
    {
        "http://127.0.0.1:5500"
    },
    AllowedScopes = new List<string>
    {
        StandardScopes.OpenId,
        StandardScopes.Profile,
        "api1"
    }
}
```

2. 前端参考：https://identityserver4.readthedocs.io/en/latest/quickstarts/4_javascript_client.html 

index.html
``` html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Index</title>
</head>
<body>
    <button id="login">Login</button>
    <button id="api">Call API</button>
    <button id="logout">Logout</button>
    <script src="oidc-client.js"></script>
    <script src="app.js"></script>
</body>
</html>
```

callback.html
``` html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>callback</title>
</head>
<body>
    <script src="oidc-client.js"></script>
    <script>
        new Oidc.UserManager().signinRedirectCallback().then(function() {
            window.location = "/implicit/index.html";
        }).catch(function(e) {
            console.error(e);
        });
    </script>
</body>
</html>
```

app.js
``` js
//添加事件
document.getElementById("login").addEventListener("click", login, false);
document.getElementById("api").addEventListener("click", api, false);
document.getElementById("logout").addEventListener("click", logout, false);

//配置
var config = {
    authority: "http://localhost:5000",
    client_id: "implicit",
    redirect_uri: "http://127.0.0.1:5500/implicit/callback.html",
    response_type: "id_token token",  //同时返回id_token和token
    scope:"openid profile api1",
    post_logout_redirect_uri : "http://127.0.0.1:5500/implicit/index.html",
};

var mgr = new Oidc.UserManager(config);

mgr.getUser().then(function (user) {
    if (user) {
        console.log(user)
    }
    else {
        console.log("User not logged in");
    }
});

//登录
function login() {
    mgr.signinRedirect();
}

//调用api
function api() {
    mgr.getUser().then(function (user) {
        var url = "http://localhost:5001/api/identity";
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url);
        xhr.onload = function () {
            log(xhr.status, JSON.parse(xhr.responseText));
        }
        xhr.setRequestHeader("Authorization", "Bearer " + user.access_token);
        xhr.send();
    });
}

//退出登录
function logout() {
    mgr.signoutRedirect();
}
```

#### 浏览器 postman测试
1. 在浏览器地址栏输入url
> https://localhost:5000/connect/authorize?
client_id=implicit_client
&redirect_uri=https%3A%2F%2Flocalhost%3A5003%2Fcallback.html
&response_type=id_token%20token
&scope=openid%20api1
&state=3d172e81b7ba4de9950402ac51bf44d5
&nonce=0df16253ac3b437bb4b703b7716ec583

2. 浏览器重定向到callback.html 并携带token
> https://localhost:5003/callback.html#
id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjM3OEFDMTAwMzdCMkNCODY3QzBFRUE3NDJGOTlDREVFIiwidHlwIjoiSldUIn0.eyJuYmYiOjE2MDk5MjY2NjMsImV4cCI6MTYwOTkyNjk2MywiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMCIsImF1ZCI6ImltcGxpY2l0X2NsaWVudCIsIm5vbmNlIjoiNTZhYjZmMmM5NTNjNGNjY2EzOGRhM2E4NGNhNzhhOTIiLCJpYXQiOjE2MDk5MjY2NjMsImF0X2hhc2giOiJ4eEdOS1daVVZ3cEZjeE0zMl93dlBBIiwic19oYXNoIjoiQ3RrN3kxUmhjNVFtbHpHNXVwdXljdyIsInNpZCI6Ijg3NUFGRjY2MjRBNkRFMUY5QTU2RUY5OTlERjFEOEM2Iiwic3ViIjoiYWRtaW4iLCJhdXRoX3RpbWUiOjE2MDk5MjY2NTYsImlkcCI6ImxvY2FsIiwiYW1yIjpbInB3ZCJdfQ.VdTuCdr12bv_GQRkjm-VlORDuKgWfGDgFrNqS7Ewwi12hqPJOx4giYGMTB0GjaDSQFnGKOJ-PSbHm8Y10vTdRTYgAvBnOGHhWA548uduKPZAK7kW1lJOd492uW8ukREGhnv7uW776tPlVpSvfOWrz7Bpugk9vHS-YZFd_Ntz6cRdj8PFcqabEPOaaopj0oMH297OZzdx6QYoTuCjMhcBOLbUU1KCKTWL7P_1Zmm5psdQB1xZ7-CMUaX1SF4g3u182fgdu9F_j0sfLyDBp4Uaqj98NWixCP2qtibv0r71WfkLjfXu9pKf592ETgkPVnHcM2uetYgxMk1E6fKMFT5Rcg
&access_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjM3OEFDMTAwMzdCMkNCODY3QzBFRUE3NDJGOTlDREVFIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MDk5MjY2NjMsImV4cCI6MTYwOTkzMDI2MywiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMCIsImNsaWVudF9pZCI6ImltcGxpY2l0X2NsaWVudCIsInN1YiI6ImFkbWluIiwiYXV0aF90aW1lIjoxNjA5OTI2NjU2LCJpZHAiOiJsb2NhbCIsInByZWZlcnJlZF91c2VybmFtZSI6IlVzZXJOYW1lIiwicm9sZSI6IlJvbGVOYW1lIiwiYXZhdGFyIjoi5aS05YOPIiwiQ05OYW1lIjoi55So5oi35aeT5ZCNIiwianRpIjoiNjQzQkIzNjg0QUFFQkJBNUI3NkUzNDhDQzZFMjczOTUiLCJzaWQiOiI4NzVBRkY2NjI0QTZERTFGOUE1NkVGOTk5REYxRDhDNiIsImlhdCI6MTYwOTkyNjY2Mywic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJhbXIiOlsicHdkIl19.Dbk5Z-rrwrfGK9yCdCllsO57dUc97f4vNGVQxiDfvUSDKZgIFcG_jLTJsK8u1fO-7t8SXDcwOLgH9fe-sLDU1Ar0QYS-SzY3A4xPVesmZsjsfivv1bQ-mO0zGsyRTETaDyit6MN32kKaPGZby7gNUbT-b3SfljvHQqNCUJVej3Nj_JPgL_ijmJa_4BKYf2P4rmtT0VR3BNRG5K9c2WVxMTbqKdPHh314Ili8rZflxAFnoDxHnTDJcDu30ahWRAXf9QcwPUyDcIT9BF1UELKn1d-1GOLpEqFhWTcMdMN7vtdohZYaImh5CC0Vdz3tJRgOe2HInFwI13kXzM1rOv98Pg
&token_type=Bearer
&expires_in=3600
&scope=openid%20profile
&state=0fab6d5e9f5f49b0b87e4c55bd1b0492
&session_state=lPA4EQhhDFfKsRxgAztjo_C1MMZXLkFJbHjW3hCVZpQ.65A0E2C92D7E559AC91812AC76D35485

3. 使用其中的access_toke即可调用api

### 混合模式（hybrid）
混合是在简化模式和授权码模式的混合。  
身份令牌（id_token）、授权码和访问令牌(access_token)是否通过浏览器传递是由ResponseType参数决定。

1. 服务端定义客户端
``` c#
new Client
{
    ClientId = "hybrid",
    ClientName = "hybrid客户端",
    AllowedGrantTypes = GrantTypes.Hybrid,
    AllowOfflineAccess = true,
    RedirectUris =
    {
        "http://locahost:5003/signin-oidc", //登录完成回调地址
    },
    PostLogoutRedirectUris =
    {
        "http://localhost:5003/signout-callback-oidc"  //退出登录回调地址
    },
    AllowedScopes = new List<string>
    {
        StandardScopes.OpenId,
        StandardScopes.Profile,
        "api1"
    }
}
```

2. 客户端配置
配置和授权码模式基本一致，唯一的差别是 ResponseType
- ResponseType三种取值：
  * code id_token： 浏览器传递code和id_token
  * code token： 浏览器传递code和token
  * code id_token token：  浏览器传递code、id_token和token

``` c#
services.AddAuthentication(options =>
    {
        options.DefaultScheme = "Cookies";
        options.DefaultChallengeScheme = "oidc";
    })
    .AddCookie("Cookies")
    .AddOpenIdConnect("oidc", options =>
    {
        options.Authority = "http://localhost:5000";
        options.ClientId = "mvc";
        options.ClientSecret = "123456";
        options.ResponseType = "code id_token token";   //授权码模式为code
        options.SaveTokens = true;
        options.RequireHttpsMetadata = false;

        //将claim信息存储到token中
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("address");
        options.Scope.Add("email");
        options.Scope.Add("api1");
        options.Scope.Add("offline_access");  //刷新Token
        options.GetClaimsFromUserInfoEndpoint = true;
    });
```

## 集成第三方

### 集成google
1. 在google控制台获取clientId和ClientSecret，并设置回调地址 http://localhost:5000/signin-google
2. 添加包 Microsoft.AspNetCore.Authentication.Google
3. 配置
``` c#
services.AddAuthentication()
    .AddGoogle("Google", options =>
    {
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.ClientId = "<insert here>";
        options.ClientSecret = "<insert here>";
    });
```

### 集成github
1. 在github控制台获取clientId和ClientSecret，并设置回调地址 http://localhost:5000/signin-github
2. 添加包 AspNet.Security.OAuth.GitHub
3. 配置
``` c#
services.AddAuthentication(opts =>
    {
        opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/signin";
        options.LogoutPath = "/signout";
    })
    .AddGitHub(options =>
    {
        options.ClientId = "<insert here>";
        options.ClientSecret = "<insert here>";
    });
```



## JWT和Reference Token
IdentityServer4 提供了俩种授权模式。默认使用的就是JWT。

- JWT
  * 优点：验证简单，不需要频繁请求授权服务器
  * 缺点：无法撤销授权
-  Reference Token
  * 优点：Token存储在授权服务器上，可随时撤销
  * 缺点：每次请求都需要验证Token，授权服务器压力较大

### Reference Token 
- 定义Client时, 设置 Client.AccessTokenType = AccessTokenType.Reference。
``` c#
new Client
{
    AccessTokenType = AccessTokenType.Reference   //设置授权类型
    ......
}
```
- 定义ApiResource时需要为每个ApiResource添加密码
``` c#
new ApiScope("api1","测试api"){
    ApiSecrets = { new Secret("123456".Sha256()) }
}
```
- Api授权验证端
使用Reference Token时验证权限应该使用包 IdentityServer4.AccessTokenValidation。
> dotnet add package IdentityServer4.AccessTokenValidation

api配置验证
``` c#
services.AddAuthentication(IdentityServerAuthenticationDefaults.AuthenticationScheme)
        .AddIdentityServerAuthentication(options => {
            options.Authority = "http://localhost:5000";
            options.ApiName = "api1";
            options.RequireHttpsMetadata = false;
            options.ApiSecret = "123456";
        });
```
- 撤销Token
``` c#
var client = new HttpClient();
var disco = await client.GetDiscoveryDocumentAsync("http://localhost:5000");

var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
var revokeAccessTokenResponse = await client.RevokeTokenAsync(new TokenRevocationRequest(){ 
        Address = disco.RevocationEndPoint,
        ClientId = "xxxxxx",
        ClientSecret = "123456",
        Token = accessToken 
    });

var refreshToken = await HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);
var revokeRefreshTokenResponse = await client.RevokeTokenAsync(new TokenRevocationRequest(){ Token = refreshToken });
```

## EF存储配置数据
IdentityServer4需要持久化的数据由两种：
- 配置数据（资源、客户端、身份），对应上下文：ConfigurationDbContext
- 操作数据（令牌、代码、授权信息），对应上下文：PersistedGrantDbContext

### Code
1. 添加依赖包
``` bash
dotnet add package IdentityServer4.EntityFramework
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
```
2. 配置
``` c#
var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
const string connectionString = @"Data Source=(LocalDb)\MSSQLLocalDB;database=IdentityServer4.Quickstart.EntityFramework-4.0.0;trusted_connection=yes;";

services.AddIdentityServer()
    .AddTestUsers(TestUsers.Users)
    .AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlServer(connectionString,
            sql => sql.MigrationsAssembly(migrationsAssembly));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b => b.UseSqlServer(connectionString,
            sql => sql.MigrationsAssembly(migrationsAssembly));
        options.EnableTokenCleanup = true;
    });
```
3. 添加迁移
``` bash
dotnet tool install --global dotnet-ef
dotnet add package Microsoft.EntityFrameworkCore.Design

dotnet ef migrations add InitialIdentityServerPersistedGrantDbMigration -c PersistedGrantDbContext -o Migrations/IdentityServer/PersistedGrantDb
dotnet ef migrations add InitialIdentityServerConfigurationDbMigration -c ConfigurationDbContext -o Migrations/IdentityServer/ConfigurationDb
```
4. 初始化数据
``` c#
private void InitializeDatabase(IApplicationBuilder app)
{
    using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
    {
        serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

        var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
        context.Database.Migrate();
        if (!context.Clients.Any())
        {
            foreach (var client in Config.Clients)
            {
                context.Clients.Add(client.ToEntity());
            }
            context.SaveChanges();
        }

        if (!context.IdentityResources.Any())
        {
            foreach (var resource in Config.IdentityResources)
            {
                context.IdentityResources.Add(resource.ToEntity());
            }
            context.SaveChanges();
        }

        if (!context.ApiScopes.Any())
        {
            foreach (var resource in Config.ApiScopes)
            {
                context.ApiScopes.Add(resource.ToEntity());
            }
            context.SaveChanges();
        }
    }
}

// Startup.cs
public void Configure(IApplicationBuilder app)
{
    InitializeDatabase(app);
}
```

### 扩展
IdentityServer中的IClientStore和IUserStore中未提供完整的数据操作方法，可以通过 IConfigurationDbContext 接口中对象直接进行数据库操作。
IdentityServer4.EntityFramework.Mappers 下提供了模型转实体（ToEntity）和实体转模型（ToModel）的扩展方法, 可直接将 IdentityServer4.Models 和 IdentityServer4.EntityFramework.Entities 下的实体进行互转。

## ProfileService
当创建令牌或者请求像Userinfo这种端点时，IdentityServer通常会需要用户的标识信息（identity information），默认情况下，IdentityServer只能从认证（authentication）Cookie中保存的claims中获取这些信息。将用户的所有可用的信息都保存到Cookie中很显然是不现实的，也是一种不好的实践，所以，IdentityServer定义了一个可扩展的点，这个点（接口）允许动态的加载用户的Claim，这个点（接口）就是IProfileService。开发人员通常实现此接口来访问包含用户数据（claims）的自定义数据库或API。

示例：
``` c#
// ProfileService.cs
public class ProfileService : IProfileService
{
    public async Task<List<Claim>> GetClaimsFromUserAsync(ApplicationUser user)
    {
        var claims = 
        return claims;
    }

    /// <summary>
    /// 获取用户Claims
    /// 用户请求userinfo endpoint时会触发该方法
    /// http://localhost:5003/connect/userinfo
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        //取得用户id
        var subjectId = context.Subject.Claims.FirstOrDefault(c => c.Type == "sub").Value;
        //根据用户id从数据库取得用户信息，写入Claim
        context.IssuedClaims =  new List<Claim> {
            new Claim(JwtClaimTypes.Subject,"UserId"),
            new Claim(JwtClaimTypes.PreferredUserName,"UserName")
            new Claim(JwtClaimTypes.Role, "RoleName"),
            new Claim("avatar", "头像"),
            new Claim("CNName", "用户姓名")
        }
    }

    /// <summary>
    /// 判断用户是否可用
    /// Identity Server会确定用户是否有效
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    public async Task IsActiveAsync(IsActiveContext context)
    {
        var subjectId = context.Subject.Claims.FirstOrDefault(c => c.Type == "sub").Value;
        var user = await _userManager.FindByIdAsync(subjectId);
        context.IsActive = user != null; //该用户是否已经激活，可用，否则不能接受token
    }
}

// Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddIdentityServer()
            //identityserver其他注入
            .Services.AddScoped<IProfileService, ProfileService>();
}
```

## ResourceOwnerPasswordValidator
如果需要自定义用户验证，需要实现IResourceOwnerPasswordValidator接口。

示例：
``` c#
// ResourceOwnerPasswordValidator.cs
public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
{
    public Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
    {
        //如果用户名admin密码123456，则验证成功，否则失败
        if (context.UserName == "admin" && context.Password == "123456")
        {
            context.Result = new GrantValidationResult(
                subject: context.UserName,
                authenticationMethod:  OidcConstants.AuthenticationMethods.Password
            );
        }
        else
        {
            context.Result = new GrantValidationResult(
                TokenRequestErrors.InvalidGrant, 
                "invalid custom credential",
            );
        }
        return Task.CompletedTask;
    }
}

// Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddIdentityServer()
            //identityserver其他注入
            .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>();
}
```

## IExtensionGrantValidato
除了系统提供的授权类型还可以自定义授权类型， 自定义授权类型需要实现接口IExtensionGrantValidato。
``` C#
public interface IExtensionGrantValidator
{
    /// <summary>
    /// 自定义授权处理方法
    ///   通过设置 context.Result 来实现授权是否成功
    /// </summary>
    /// <param name="request"></param>
    Task ValidateAsync(ExtensionGrantValidationContext context);

   
    /// <value>
    /// The type of the grant.
    /// </value>
    string GrantType { get; }
}

public class DelegationGrantValidator : IExtensionGrantValidator
{
    /// <summary>
    /// 授权类型
    /// </summary>
    public string GrantType => "delegation";

    public async Task ValidateAsync(ExtensionGrantValidationContext context)
    {
        //验证处理
        if (验证失败)
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant);
        }
        else{
            context.Result = new GrantValidationResult(sub, GrantType);
        }
    }
}

```  
注册完成后注册到容器中
``` c#
services.AddIdentityServer()
        .AddExtensionGrantValidator<DelegationGrantValidator>();
```

定义客户端
``` c#
var client = new client
{
    AllowedGrantTypes = { "delegation" },
    ......
}
```
调用
``` C#
public async Task<TokenResponse> DelegateAsync(string userToken)
{
    ......
    var client = new TokenClient(disco.TokenEndpoint, "api1.client", "secret");
    return await client.RequestCustomGrantAsync("delegation", "api2", payload);
}
```  

## 问题

### RequirePkce
RequirePkce 在指定基于授权码的令牌是否需要验证密钥，默认为true.  
在4.x版本中会报错：
> Sorry, there was an error: invalid_request  
code challenge required

解决办法：
设置 Client.RequirePkce = false。 这样服务端便不需要客户端提供code challeng。

### ResponseType
在Hybrid模式下只要ResponseType包含token都会报错:
> Sorry, there was an error: invalid_request  
Client not configured to receive access token via browser

解决办法： 
设置 Client.AllowAccessTokensViaBrowser = true。 这样服务端就允许token通过浏览器传递

### 在3.1.x 到 4.x 的变更
在3.1.x 到 4.x 的变更中，ApiResource 的 Scope 正式独立出来为 ApiScope 对象，区别ApiResource 和 Scope的关系, Scope 是属于ApiResource 的一个属性，可以包含多个Scope。

所以在配置ApiResource、ApiScope、Clients中，我们有些地方需要注意：
``` c#
//3.x
services.AddIdentityServer()
    .AddInMemoryApiResources(new ApiResource[]{
        new ApiResource("api1", "api1")
    });


 //4.x
 services.AddIdentityServer()
    .AddInMemoryApiResources(new ApiResource[]{
        new ApiResource("api1", "api1") {
            Scopes={"client_scope1" }
        }
    })
    // 4.x新增方法
    .AddInMemoryApiScopes(new ApiScope[]{
        new ApiScope("client_scope1")
    });
```
- 如果在4.x版本中，不添加ApiScopes方法的话，在获取token令牌的时候一直“无效的scope”等错误
- 在授权访问保护资源的时候，如果ApiResource中不添加Scopes, 会一直报Audience validation failed错误，得到401错误，所以在4.x版本中写法要不同于

## 参考
- https://identityserver4.readthedocs.io/en/latest/index.html
- https://www.cnblogs.com/stulzq/p/8119928.html
- https://www.cnblogs.com/i3yuan/category/1777690.html
