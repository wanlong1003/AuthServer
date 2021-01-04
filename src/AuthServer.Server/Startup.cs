using AuthServer.Server.Models;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication.QQ;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
                        AllowedScopes = { "api1", StandardScopes.OpenId, StandardScopes.Profile }
                    },
                    new Client(){
                        ClientId = "code_client",
                        ClientName = "Code Client",
                        ClientSecrets = { new Secret("123456".Sha256())},
                        AllowedGrantTypes = GrantTypes.Code,
                        RedirectUris = { "https://localhost:5002/signin-oidc" },
                        PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },
                        AllowOfflineAccess = true,
                        AlwaysIncludeUserClaimsInIdToken = true,
                        RequireConsent = true,
                        AllowedScopes = { "api1", StandardScopes.OpenId, StandardScopes.Profile }
                    },
                    new Client(){
                        ClientId = "implicit_client",
                        ClientName = "Implicit Client",
                        AllowedGrantTypes = GrantTypes.Implicit,
                        AllowAccessTokensViaBrowser = true,
                        RequireConsent = true,
                        RedirectUris = { "https://localhost:5003/callback.html" },
                        PostLogoutRedirectUris = { "https://localhost:5003/index.html" },
                        AllowedCorsOrigins = { "https://localhost:5003" },
                        AllowedScopes = { "api1", StandardScopes.OpenId, StandardScopes.Profile },
                    },
                    new Client(){
                        ClientId = "hybrid_client",
                        ClientName = "Hybrid Client",
                        ClientSecrets = { new Secret("123456".Sha256())},
                        AllowedGrantTypes = GrantTypes.Hybrid,
                        AllowOfflineAccess = true,
                        RequireConsent = true,
                        RequirePkce = false,
                        AllowAccessTokensViaBrowser = true,
                        RedirectUris = { "https://localhost:5004/signin-oidc" },
                        PostLogoutRedirectUris = { "https://localhost:5004/signout-callback-oidc" },
                        AllowedCorsOrigins = { "https://localhost:5004" },
                        AllowedScopes = { "api1", StandardScopes.OpenId, StandardScopes.Profile }
                    },
                })
                .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                .Services.AddScoped<IProfileService, ProfileService>();

            services.AddAuthentication()
                //.AddGoogle("Google", options =>
                //{
                //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                //    options.ClientId = "";
                //    options.ClientSecret = "";
                //})
                //.AddFacebook("Facebook", options =>
                //{
                //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                //    options.ClientId = "";
                //    options.ClientSecret = "";
                //})
                //.AddMicrosoftAccount("MicrosoftAccount", options =>
                //{
                //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                //    options.ClientId = "";
                //    options.ClientSecret = "";
                //})
                //.AddTwitter("Twitter", options =>
                //{
                //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                //    options.ConsumerKey = "";
                //    options.ConsumerSecret = "";
                //})
                .AddLinkedIn("LinkedIn", options =>
                {
                    options.ClientId = "86q7iml2m0t9fe";
                    options.ClientSecret = "528EI4X9BUzjCesM";
                })
                //.AddGitHub(options =>
                //{
                //    options.ClientId = "648c067bd022b25f09d7";
                //    options.ClientSecret = "bdbb069548d10fbcf541eb7e6badc6e4464a9771";
                //});
                .AddGitHub(options =>
                {
                    options.ClientId = "94d04883ecf82b593fc8";
                    options.ClientSecret = "efcf19cf1de31ba07337d6ed5f8593129017d8f3";
                });
            //.AddQQ("QQ", options =>
            // {
            //     options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //     options.AppId = "";
            //     options.AppKey = "";
            // });

            services.AddCors();
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseCors(configurePolicy =>
            {
                configurePolicy.AllowAnyOrigin();
                configurePolicy.AllowAnyMethod();
                configurePolicy.AllowAnyHeader();
            });
            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseRouting();
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
