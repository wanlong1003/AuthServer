using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthServer.Example.Client.Hybrid
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
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
               .AddCookie("Cookies")
               .AddOpenIdConnect("oidc", options =>
               {
                   options.SignInScheme = "Cookies";

                   options.Authority = "https://localhost:5000";
                   options.ClientId = "hybrid_client";
                   options.ClientSecret = "123456";
                   options.ResponseType = "code id_token";
                   options.SaveTokens = true;
                   options.GetClaimsFromUserInfoEndpoint = true;
                   options.RequireHttpsMetadata = false;
                   options.Scope.Add("openid");
                   options.Scope.Add("profile");                 
               });

            services.AddAuthorization();
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseDeveloperExceptionPage();
            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
