// ============================================================
// Program.cs — Application entry point and dependency injection
// ============================================================
// This file wires up all services and middleware. The key design
// decision is that Vulnerable and Secure implementations of the
// same interface are registered here based on ASPNETCORE_ENVIRONMENT.
// Controllers depend on interfaces, not concrete classes, so they
// don't need to know which implementation they're using.
// ============================================================

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Portal.Web.Configuration;
using Portal.Web.Data;
using Portal.Web.Models;
using Portal.Web.Services;

var builder = WebApplication.CreateBuilder(args);

// Read the environment name once. Every mode-switching decision below derives from this.
// "Secure" means all vulnerabilities are remediated.
// Anything else (Development, Production, etc.) means Vulnerable mode is active.
var isSecure = builder.Environment.EnvironmentName.Equals("Secure", StringComparison.OrdinalIgnoreCase);

builder.Services.AddControllersWithViews();

// ------------------------------------------------------------------
// Database — SQLite via Entity Framework Core
// ------------------------------------------------------------------
// EnsureCreated() (called at startup below) creates the schema from
// the entity model. No 'dotnet ef migrations' command is needed.
// Connection string falls back to "portal.db" in the working directory
// if the key is absent from appsettings.json.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=portal.db"));

// ------------------------------------------------------------------
// ASP.NET Core Identity — authentication and user management
// ------------------------------------------------------------------
// Identity handles password hashing, sign-in cookies, and role checks.
// Lockout settings are configured here but only take effect when
// lockoutOnFailure: true is passed to PasswordSignInAsync (Secure mode).
// In Vulnerable mode, PasswordSignInAsync is called with lockoutOnFailure: false,
// so these settings are bypassed — demonstrating Vulnerability #5.
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password requirements — applied in both modes during account creation
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;

    // Lockout settings — ONLY enforced when lockoutOnFailure: true is used (Secure mode)
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.AllowedForNewUsers = true;

    // Disable email confirmation so demo accounts work immediately after seeding
    options.SignIn.RequireConfirmedAccount = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ------------------------------------------------------------------
// Identity cookie configuration
// ------------------------------------------------------------------
// These settings apply to the main Identity session cookie.
// Note: HttpOnly=true here is intentional — this is the secure session cookie.
// The WEAK cookie from Vulnerability #8 is a SEPARATE custom cookie
// (RememberToken) set in AccountController, not this one.
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.Cookie.HttpOnly = true;              // Session cookie — always HttpOnly
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
});

// ------------------------------------------------------------------
// SecurityProfile — the single source of truth for which mode is active
// ------------------------------------------------------------------
// Registered as a Singleton so it is created once and reused.
// Controllers and views inject this to conditionally apply or skip
// security checks without needing to re-read the environment name.
builder.Services.AddSingleton<SecurityProfile>();

// ------------------------------------------------------------------
// Service registration — this is the core of the dual-mode pattern
// ------------------------------------------------------------------
// By registering different concrete classes behind the same interface,
// controllers stay unchanged between modes. The only place that knows
// which implementation is active is right here.
if (isSecure)
{
    // Secure: parameterised SQL queries, extension whitelist, GUID filenames
    builder.Services.AddScoped<IEmployeeSearchService, SecureEmployeeSearchService>();
    builder.Services.AddScoped<IFileUploadService, SecureFileUploadService>();
}
else
{
    // Vulnerable: raw string-concatenated SQL, all file types accepted, original filename stored
    builder.Services.AddScoped<IEmployeeSearchService, VulnerableEmployeeSearchService>();
    builder.Services.AddScoped<IFileUploadService, VulnerableFileUploadService>();
}

var app = builder.Build();

// ------------------------------------------------------------------
// Database initialisation and seeding
// ------------------------------------------------------------------
// Runs synchronously at startup before the first request is handled.
// EnsureCreated() creates all tables if the database file doesn't exist.
// SeedData.Initialize() creates roles, users, announcements, and expenses
// if they don't already exist — safe to call on every startup.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.EnsureCreatedAsync();
    await SeedData.Initialize(scope.ServiceProvider);
}

// Show detailed exception pages in development; use a generic handler otherwise.
// The Secure environment doesn't count as Development, so it uses the generic handler.
if (!app.Environment.IsDevelopment() && !isSecure)
    app.UseExceptionHandler("/Home/Error");

// ------------------------------------------------------------------
// Middleware pipeline — ORDER MATTERS
// ------------------------------------------------------------------
// UseAuthentication must come before UseAuthorization.
// UseStaticFiles serves wwwroot/ (including the vulnerable /uploads/ directory).
app.UseHttpsRedirection();
app.UseStaticFiles();  // Serves wwwroot/ — in Vulnerable mode, /uploads/ is public
app.UseRouting();
app.UseAuthentication(); // Reads the Identity cookie and populates User.Identity
app.UseAuthorization();  // Evaluates [Authorize] attributes

app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");

app.Run();
