using AuthServer.Server.Models;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static IdentityServer4.IdentityServerConstants;

namespace AuthServer.Server
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryIdentityResources(new IdentityResource[] {
                    new IdentityResources.OpenId(),
                    new IdentityResources.Profile(),
                    new IdentityResources.Email(),
                    new IdentityResources.Address()
                })
                .AddInMemoryApiScopes(new ApiScope[]{
                    new ApiScope("api1","API2"),
                    new ApiScope("api2","API1")
                })
                //添加客户端
                .AddInMemoryClients(new Client[]{
                     new Client(){
                        ClientId = "client",
                        ClientName = "Client",
                        ClientSecrets = { new Secret("123456".Sha256())},
                        AllowedGrantTypes = GrantTypes.ClientCredentials,
                        AllowedScopes = { "api1" }
                    },
                    new Client(){
                        ClientId = "password_client",
                        ClientName = "Password Client",
                        ClientSecrets = { new Secret("123456".Sha256())},
                        AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                        AllowedScopes = { "api1", StandardScopes.OpenId }
                    },
                    new Client(){
                        ClientId = "code_client",
                        ClientName = "Code Client",
                        ClientSecrets = { new Secret("123456".Sha256())},
                        AllowedGrantTypes = GrantTypes.Code,
                        RedirectUris = { "http://localhost:5002/signin-oidc" },
                        PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },
                        AllowOfflineAccess = true,  //启用刷新token
                        AlwaysIncludeUserClaimsInIdToken = true,  //Token中是否包含用户Claim信息
                        RequireConsent = true,  //是否需要用户同意，单点登录设置为false
                        AllowedScopes = { "api1", StandardScopes.OpenId }
                    },
                    new Client(){
                        ClientId = "implicit_client",
                        ClientName = "Implicit Client",
                        AllowedGrantTypes = GrantTypes.Implicit,
                        AllowAccessTokensViaBrowser = true,  //是否通过浏览器返回access_token
                        RequireConsent = true,  //是否需要用户同意
                        RedirectUris = { "https://localhost:5003/callback.html" },
                        PostLogoutRedirectUris = { "https://localhost:5003/index.html" },
                        AllowedCorsOrigins = { "https://localhost:5003" },
                        AllowedScopes = { "api1", StandardScopes.OpenId }
                    },
                    new Client(){
                        ClientId = "hybrid_client",
                        ClientName = "Hybrid Client",
                        ClientSecrets = { new Secret("123456".Sha256())},
                        AllowedGrantTypes = GrantTypes.Hybrid,
                        AllowOfflineAccess = true,
                        RedirectUris = { "http://localhost:5004/signin-oidc" },
                        PostLogoutRedirectUris = { "http://localhost:5004/signout-callback-oidc" },
                        AllowedScopes = { "api1", StandardScopes.OpenId }
                    },
                })
                .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                .Services.AddScoped<IProfileService, ProfileService>();

            services.AddControllersWithViews();
            services.AddCors();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseDeveloperExceptionPage();
            app.UseHttpsRedirection();
            app.UseCors(configurePolicy =>
            {
                configurePolicy.AllowAnyOrigin();
                configurePolicy.AllowAnyMethod();
                configurePolicy.AllowAnyHeader();
                //configurePolicy.AllowCredentials();
            });
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthorization();
            app.UseAuthorization();
            app.UseIdentityServer();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
