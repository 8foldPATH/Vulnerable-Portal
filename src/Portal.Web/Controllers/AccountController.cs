// ============================================================
// AccountController.cs — Login, logout, and remember-me
// ============================================================
// Contains two active vulnerabilities that are switched by SecurityProfile:
//
// VULNERABILITY #5 — No Account Lockout (OWASP A07)
//   PasswordSignInAsync is called with lockoutOnFailure: false in Vulnerable mode.
//   Identity only increments the failed-attempt counter when this is true,
//   so an attacker can submit unlimited password guesses. Burp Suite Intruder
//   or a curl loop will find the password without any lockout ever triggering.
//   Fix: pass lockoutOnFailure: true (Secure mode).
//
// VULNERABILITY #8 — Weak Remember-Me Token (OWASP A07)
//   After a successful login with "Remember me" checked, a custom cookie
//   named RememberToken is set with the value Base64(email) and HttpOnly=false.
//   Because HttpOnly=false, any JavaScript on the page — including an injected
//   XSS payload from Vulnerability #2 — can read this cookie via document.cookie
//   and decode the user's email with atob(). This makes XSS more damaging.
//   Fix: use Identity's built-in persistent cookie (isPersistent: true), which
//   is HttpOnly=true and contains an opaque cryptographic token, not user data.
// ============================================================

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Portal.Web.Configuration;
using Portal.Web.Models;
using Portal.Web.Models.ViewModels;

namespace Portal.Web.Controllers;

public class AccountController : Controller
{
    private readonly SignInManager<ApplicationUser> _signIn;
    private readonly SecurityProfile _profile;

    public AccountController(SignInManager<ApplicationUser> signIn, SecurityProfile profile)
    {
        _signIn = signIn;
        _profile = profile;
    }

    // GET /Account/Login — render the login form
    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    // POST /Account/Login — authenticate the submitted credentials
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        if (!ModelState.IsValid) return View(model);

        // -------------------------------------------------------
        // VULNERABILITY #5 — No Account Lockout
        // -------------------------------------------------------
        // The two key parameters here differ between modes:
        //
        //   isPersistent:
        //     Vulnerable: always false — Identity never sets a persistent cookie,
        //       even when RememberMe is checked. We set our own insecure cookie below.
        //     Secure: true when RememberMe is checked — Identity sets a persistent
        //       HttpOnly cookie with a cryptographic token.
        //
        //   lockoutOnFailure:
        //     Vulnerable: false — Identity skips the failed-attempt counter entirely.
        //       No matter how many wrong passwords are tried, the account never locks.
        //     Secure: true — Identity increments AccessFailedCount on each failure.
        //       After 5 failures the account is locked for 5 minutes (configured in Program.cs).
        var result = await _signIn.PasswordSignInAsync(
            model.Email,
            model.Password,
            isPersistent: _profile.IsSecure && model.RememberMe,
            lockoutOnFailure: _profile.IsSecure
        );

        if (result.Succeeded)
        {
            // -------------------------------------------------------
            // VULNERABILITY #8 — Weak Remember-Me Token
            // -------------------------------------------------------
            // In Vulnerable mode, if "Remember me" is checked, we set a
            // custom cookie in addition to the Identity session cookie.
            //
            // The token is simply the email address Base64-encoded:
            //   Convert.ToBase64String(Encoding.UTF8.GetBytes("admin@acme.com"))
            //   → "YWRtaW5AYWNtZS5jb20="
            //
            // Two problems:
            //   1. The email is recoverable: atob("YWRtaW5AYWNtZS5jb20=") = "admin@acme.com"
            //   2. HttpOnly=false means JavaScript can access document.cookie,
            //      so any XSS payload on the page can steal and decode this token.
            if (_profile.IsVulnerable && model.RememberMe)
            {
                var token = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(model.Email));
                Response.Cookies.Append("RememberToken", token, new CookieOptions
                {
                    Expires = DateTimeOffset.UtcNow.AddDays(30),
                    HttpOnly = false,            // VULNERABLE: readable by JavaScript
                    SameSite = SameSiteMode.Lax,
                    Secure = Request.IsHttps
                });
            }
            // In Secure mode, isPersistent: true above caused Identity to set its own
            // cookie (.AspNetCore.Identity.Application) which is HttpOnly=true by default
            // and contains an opaque token — no user data is decodable from it.

            // Honour the returnUrl so the login page redirect loop works correctly.
            // Url.IsLocalUrl() prevents open redirect attacks.
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            return RedirectToAction("Index", "Home");
        }

        // IsLockedOut is only ever true in Secure mode (lockoutOnFailure: true)
        if (result.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty, "Account locked due to too many failed attempts. Try again in 5 minutes.");
            return View(model);
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return View(model);
    }

    // POST /Account/Logout — clear both the Identity cookie and the custom remember-me cookie
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signIn.SignOutAsync();
        Response.Cookies.Delete("RememberToken"); // Remove the vulnerable cookie if present
        return RedirectToAction("Login");
    }

    // GET /Account/AccessDenied — shown by Identity when [Authorize] is denied
    [HttpGet]
    public IActionResult AccessDenied() => View();
}
