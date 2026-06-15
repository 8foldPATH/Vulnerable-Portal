// ============================================================
// EmployeesController.cs — Employee directory search
// ============================================================
// This controller is intentionally thin. The SQL injection vulnerability
// (Vulnerability #1) lives in the service layer, not here. The controller
// depends on IEmployeeSearchService, and Program.cs injects either:
//   Vulnerable mode → VulnerableEmployeeSearchService (raw string-concat SQL)
//   Secure mode     → SecureEmployeeSearchService (parameterised EF Core query)
//
// This pattern demonstrates the Dependency Inversion Principle: the
// controller depends on an abstraction, not a concrete implementation.
// Swapping the security posture requires changing only the DI registration
// in Program.cs — no changes to this controller or its tests.
// ============================================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Portal.Web.Services;

namespace Portal.Web.Controllers;

[Authorize]
public class EmployeesController : Controller
{
    // IEmployeeSearchService is injected by DI. The controller has no
    // knowledge of whether it's getting the vulnerable or secure implementation.
    private readonly IEmployeeSearchService _search;

    public EmployeesController(IEmployeeSearchService search) => _search = search;

    // GET /Employees?q=<search-term>
    // The ?q= parameter is passed straight to SearchAsync().
    // In Vulnerable mode SearchAsync() interpolates it into SQL — see VulnerableEmployeeSearchService.
    // In Secure mode it's passed as a parameterised bind variable — see SecureEmployeeSearchService.
    public async Task<IActionResult> Index(string? q)
    {
        ViewBag.Query = q; // Used in the view to pre-populate the search box and show result count
        var results = await _search.SearchAsync(q);
        return View(results);
    }
}
