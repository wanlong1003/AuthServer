using AuthServer.Server.Models;
using IdentityServer4.Models;
using IdentityServer4.Services;
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
                        RedirectUris = { "http://localhost:5002/signin-oidc" },
                        PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },
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
                        RedirectUris = { "http://localhost:5003/callback.html" },
                        PostLogoutRedirectUris = { "http://localhost:5003/index.html" },
                        AllowedCorsOrigins = { "http://localhost:5003" },
                        AllowedScopes = { "api1", StandardScopes.OpenId, StandardScopes.Profile },
                    },
                    new Client(){
                        ClientId = "hybrid_client",
                        ClientName = "Hybrid Client",
                        ClientSecrets = { new Secret("123456".Sha256())},
                        AllowedGrantTypes = GrantTypes.Hybrid,
                        AllowOfflineAccess = true,
                        RedirectUris = { "http://localhost:5004/signin-oidc" },
                        PostLogoutRedirectUris = { "http://localhost:5004/signout-callback-oidc" },
                        AllowedScopes = { "api1", StandardScopes.OpenId, StandardScopes.Profile }
                    },
                })
                .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                .Services.AddScoped<IProfileService, ProfileService>();

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
