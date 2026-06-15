// ============================================================
// SecureEmployeeSearchService.cs — Remediation for Vulnerability #1
// ============================================================
// OWASP A03 — Injection (remediated)
//
// The fix: use EF Core's LINQ query builder instead of raw SQL.
// EF.Functions.Like() translates to a LIKE query with a parameterised
// bind variable — the user's input is never concatenated into SQL text.
//
// When an attacker enters:   ' OR '1'='1
// EF Core generates:
//   SELECT * FROM "AspNetUsers" WHERE "FullName" LIKE @__Format_1 ESCAPE '\'
//   @__Format_1 = '%'' OR ''1''=''1%'
// The single quotes are safely included in the parameter value and
// the database treats the entire input as a literal string to match against,
// not as SQL grammar. No rows match, so nothing is returned.
//
// Registered in DI by Program.cs when ASPNETCORE_ENVIRONMENT=Secure.
// ============================================================

using Microsoft.EntityFrameworkCore;
using Portal.Web.Data;
using Portal.Web.Models;

namespace Portal.Web.Services;

public class SecureEmployeeSearchService : IEmployeeSearchService
{
    private readonly ApplicationDbContext _db;

    public SecureEmployeeSearchService(ApplicationDbContext db) => _db = db;

    public async Task<IEnumerable<ApplicationUser>> SearchAsync(string? query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return await _db.Users.ToListAsync();

        // SECURE: EF Core builds a parameterised query.
        // The $"%" string interpolation here is in C# — it builds the LIKE pattern
        // ("%query%") as a C# string BEFORE it reaches EF Core, which then passes
        // that complete pattern as a bind variable to the database.
        // The crucial difference from the vulnerable version is that the ENTIRE
        // pattern (including user input) is the parameter value — not part of the SQL.
        return await _db.Users
            .Where(u => EF.Functions.Like(u.FullName, $"%{query}%"))
            .ToListAsync();
    }
}
