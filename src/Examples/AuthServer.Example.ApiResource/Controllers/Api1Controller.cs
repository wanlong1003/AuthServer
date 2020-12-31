using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Example.ApiResource.Controllers
{
    [Authorize(policy: "api1")]
    [Route("api/[controller]")]
    [ApiController]
    public class Api1Controller : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("API1");
        }
    }
}
