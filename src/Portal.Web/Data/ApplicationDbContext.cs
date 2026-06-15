// ============================================================
// ApplicationDbContext.cs — Entity Framework Core database context
// ============================================================
// Extends IdentityDbContext so that ASP.NET Identity tables
// (AspNetUsers, AspNetRoles, AspNetUserRoles, etc.) are created
// automatically by EnsureCreated() alongside our custom tables.
//
// ApplicationUser extends IdentityUser with the custom fields
// FullName, Department, and IsHrManager. Those extra columns
// are added to the AspNetUsers table by EF Core.
// ============================================================

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Portal.Web.Models;

namespace Portal.Web.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    // Custom application tables — Identity tables are inherited from IdentityDbContext
    public DbSet<Announcement> Announcements { get; set; }
    public DbSet<ExpenseReport> ExpenseReports { get; set; }
    public DbSet<FileAttachment> FileAttachments { get; set; }
}
