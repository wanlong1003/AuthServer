using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthServer.Example.Client.Hybrid.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            ViewBag.AccessToken = HttpContext.GetTokenAsync("access_token").GetAwaiter().GetResult();
            ViewBag.RefreshToken = HttpContext.GetTokenAsync("refresh_token").GetAwaiter().GetResult();
            ViewBag.IdToken = HttpContext.GetTokenAsync("id_token").GetAwaiter().GetResult();
            return View();
        }
    }
}
