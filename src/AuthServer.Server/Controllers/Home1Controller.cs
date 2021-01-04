using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Server.Controllers
{
    [Authorize]
    public class Home1Controller : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
