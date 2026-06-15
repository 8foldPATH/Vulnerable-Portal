// ============================================================
// VulnerableEmployeeSearchService.cs — VULNERABILITY #1: SQL Injection
// ============================================================
// OWASP A03 — Injection
//
// The flaw: the search query from the URL parameter is interpolated
// directly into a raw SQL string using a C# interpolated string ($"...").
// This means the database receives the user's input as part of the SQL
// grammar itself, not as a safely-quoted value.
//
// When an attacker enters:   ' OR '1'='1
// The resulting SQL becomes:
//   SELECT * FROM AspNetUsers WHERE FullName LIKE '%' OR '1'='1%'
// The condition '1'='1' is always true, so every row is returned.
//
// A UNION attack can dump additional columns from the same or other tables:
//   ' UNION SELECT Id,UserName,Email,FullName,Department,0,'' FROM AspNetUsers--
//
// This implementation is registered in DI by Program.cs when the
// environment is NOT "Secure". Compare with SecureEmployeeSearchService
// which uses a parameterised query and is immune to these attacks.
// ============================================================

using Microsoft.EntityFrameworkCore;
using Portal.Web.Data;
using Portal.Web.Models;

namespace Portal.Web.Services;

public class VulnerableEmployeeSearchService : IEmployeeSearchService
{
    private readonly ApplicationDbContext _db;

    public VulnerableEmployeeSearchService(ApplicationDbContext db) => _db = db;

    public async Task<IEnumerable<ApplicationUser>> SearchAsync(string? query)
    {
        // Empty search returns all users — expected behaviour
        if (string.IsNullOrWhiteSpace(query))
            return await _db.Users.ToListAsync();

        // VULNERABLE: The query string is interpolated directly into SQL.
        // Whatever the user types becomes part of the SQL statement.
        // There is no escaping, quoting, or parameterisation.
        //
        // Exploit: try entering  ' OR '1'='1  in the search box.
        // The WHERE clause becomes: LIKE '%' OR '1'='1%'  which is always true.
        var sql = $"SELECT * FROM AspNetUsers WHERE FullName LIKE '%{query}%'";

        // FromSqlRaw sends this string to SQLite without any further processing.
        // EF Core's safe alternative would be FromSqlInterpolated or a LINQ query.
        return await _db.Users.FromSqlRaw(sql).ToListAsync();
    }
}
