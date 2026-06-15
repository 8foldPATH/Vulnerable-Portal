// ============================================================
// SecurityProfile.cs — Application-wide mode switch
// ============================================================
// This class is the single source of truth for whether the app
// is running in Vulnerable or Secure mode. It is registered as
// a Singleton in Program.cs and injected wherever a controller
// or Razor view needs to conditionally enable or skip a flaw.
//
// Mode is determined by ASPNETCORE_ENVIRONMENT:
//   "Secure"      → all security controls active
//   anything else → all vulnerabilities active (default for dev)
//
// Why a class rather than just reading IWebHostEnvironment directly?
// Centralising the decision here means the string comparison happens
// once, and all consumers get a simple boolean (IsVulnerable/IsSecure).
// ============================================================

namespace Portal.Web.Configuration;

public enum SecurityProfileType { Vulnerable, Secure }

public class SecurityProfile
{
    public SecurityProfileType Type { get; }

    // Convenience properties used throughout controllers and views
    public bool IsVulnerable => Type == SecurityProfileType.Vulnerable;
    public bool IsSecure => Type == SecurityProfileType.Secure;

    // IWebHostEnvironment is a framework singleton — safe to inject here
    public SecurityProfile(IWebHostEnvironment env)
    {
        Type = env.EnvironmentName.Equals("Secure", StringComparison.OrdinalIgnoreCase)
            ? SecurityProfileType.Secure
            : SecurityProfileType.Vulnerable;
    }
}
