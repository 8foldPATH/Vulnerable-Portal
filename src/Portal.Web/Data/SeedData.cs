// ============================================================
// SeedData.cs — Demo data for assessment exercises
// ============================================================
// Called from Program.cs on every startup. All operations are
// idempotent — they check whether data already exists before
// inserting, so restarting the app never duplicates records.
//
// Seeded data is deliberately structured to make each vulnerability
// demonstrable out of the box:
//   - Three users across two roles enable IDOR and admin bypass demos
//   - Three expense reports with sequential IDs (1, 2, 3) are easy
//     to enumerate manually in the IDOR exercise
//   - Announcements give an XSS injection target from the start
// ============================================================

using Microsoft.AspNetCore.Identity;
using Portal.Web.Models;

namespace Portal.Web.Data;

public static class SeedData
{
    public static async Task Initialize(IServiceProvider services)
    {
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var db = services.GetRequiredService<ApplicationDbContext>();

        // ----------------------------------------------------------
        // Roles — Admin gives access to the admin panel in Secure mode;
        // Employee is the standard role for all other accounts.
        // ----------------------------------------------------------
        foreach (var role in new[] { "Admin", "Employee" })
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        // ----------------------------------------------------------
        // Users — CreateUser returns null if the account already exists,
        // so the AddToRoleAsync calls are safely skipped on subsequent startups.
        // ----------------------------------------------------------

        // Admin account — can access /Admin in Secure mode
        var admin = await CreateUser(userManager, "admin@acme.com", "Admin123!", "Alice Admin", "IT", false);
        if (admin != null) await userManager.AddToRoleAsync(admin, "Admin");

        // Employee 1 — used as the primary test account in most exercises
        var emp1 = await CreateUser(userManager, "employee1@acme.com", "Employee123!", "Bob Builder", "Engineering", false);
        if (emp1 != null) await userManager.AddToRoleAsync(emp1, "Employee");

        // Employee 2 — IsHrManager=true; her expense report (ID 3) is the IDOR target
        var emp2 = await CreateUser(userManager, "employee2@acme.com", "Employee123!", "Carol Carter", "HR", true);
        if (emp2 != null) await userManager.AddToRoleAsync(emp2, "Employee");

        // ----------------------------------------------------------
        // Announcements — the XSS injection target (Vulnerability #2)
        // These provide realistic content so the app looks like a real portal,
        // and give an attacker somewhere to post their XSS payload.
        // ----------------------------------------------------------
        if (!db.Announcements.Any())
        {
            // We need Alice's ID to set the AuthorId foreign key
            var authorId = (await userManager.FindByEmailAsync("admin@acme.com"))!.Id;
            db.Announcements.AddRange(
                new Announcement
                {
                    Title = "Q4 All-Hands Meeting",
                    Content = "Join us Friday at 3 PM for our quarterly review. Agenda will be circulated on Thursday. Please bring your team updates.",
                    AuthorId = authorId,
                    CreatedAt = DateTime.UtcNow.AddDays(-5)
                },
                new Announcement
                {
                    Title = "New Expense Policy",
                    Content = "Expenses above £500 now require manager sign-off before submission. Please review the updated policy document in the HR portal and update any pending claims.",
                    AuthorId = authorId,
                    CreatedAt = DateTime.UtcNow.AddDays(-2)
                },
                new Announcement
                {
                    Title = "Office Closure — Bank Holiday",
                    Content = "The office will be closed on the upcoming bank holiday. Remote work is permitted. Please ensure all critical tasks are covered.",
                    AuthorId = authorId,
                    CreatedAt = DateTime.UtcNow.AddDays(-1)
                }
            );
            await db.SaveChangesAsync();
        }

        // ----------------------------------------------------------
        // Expense reports — the IDOR target (Vulnerability #4)
        // Three reports are seeded with sequential IDs (1, 2, 3).
        // Logging in as Bob (employee1) and navigating to /Expenses/Details/3
        // demonstrates that Carol's (employee2) report is accessible.
        // ----------------------------------------------------------
        if (!db.ExpenseReports.Any())
        {
            var adminUser = await userManager.FindByEmailAsync("admin@acme.com");
            var bobUser = await userManager.FindByEmailAsync("employee1@acme.com");
            var carolUser = await userManager.FindByEmailAsync("employee2@acme.com");

            if (adminUser != null && bobUser != null && carolUser != null)
            {
                db.ExpenseReports.AddRange(
                    new ExpenseReport
                    {
                        EmployeeId = adminUser.Id,          // Report #1 — belongs to Alice (Admin)
                        Description = "Laptop stand and peripherals for home office",
                        Amount = 145.00m,
                        Status = "Approved",
                        CreatedAt = DateTime.UtcNow.AddDays(-10)
                    },
                    new ExpenseReport
                    {
                        EmployeeId = bobUser.Id,            // Report #2 — belongs to Bob (employee1)
                        Description = "Client lunch — Project Falcon kickoff",
                        Amount = 87.50m,
                        Status = "Pending",
                        CreatedAt = DateTime.UtcNow.AddDays(-3)
                    },
                    new ExpenseReport
                    {
                        EmployeeId = carolUser.Id,          // Report #3 — belongs to Carol (employee2)
                        Description = "HR conference travel and accommodation",
                        Amount = 312.00m,
                        Status = "Pending",
                        CreatedAt = DateTime.UtcNow.AddDays(-1)
                    }
                );
                await db.SaveChangesAsync();
            }
        }
    }

    // Creates a user only if one with that email doesn't already exist.
    // Returns null on a subsequent startup when the account is found — callers must null-check.
    private static async Task<ApplicationUser?> CreateUser(
        UserManager<ApplicationUser> um, string email, string password,
        string fullName, string dept, bool isHr)
    {
        if (await um.FindByEmailAsync(email) != null) return null;

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FullName = fullName,
            Department = dept,
            IsHrManager = isHr,
            EmailConfirmed = true   // Skip email confirmation so demo accounts work immediately
        };
        await um.CreateAsync(user, password);
        return await um.FindByEmailAsync(email);
    }
}
