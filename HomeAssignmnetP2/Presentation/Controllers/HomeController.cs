using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Presentation.Models;
using System.Diagnostics;
using System.Text;

namespace Presentation.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public HomeController(ILogger<HomeController> logger, UserManager<IdentityUser> userManager, IWebHostEnvironment webHostEnvironment)
        {
            _logger = logger;
            _userManager = userManager;
            _webHostEnvironment = webHostEnvironment;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Vulnerable(string name)
        {
            ViewBag.Name = name;
            return View();
        }

        [Authorize(Roles = "Admin")]
        public IActionResult Secret()
        {
            string secretInfo = "Andrea Baldacchino";
            return Content(secretInfo);
        }

        [HttpPost]
        public IActionResult Malicious(string payload)
        {
            string path = Path.Combine(_webHostEnvironment.ContentRootPath, "malicious.txt");
            System.IO.File.WriteAllText(path, payload, Encoding.UTF8);
            return Ok();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
