using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Portal.Web.Controllers;

[Authorize]
public class HomeController : Controller
{
    public IActionResult Index() => View();
}
