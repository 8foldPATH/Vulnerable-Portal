using Portal.Web.Models;

namespace Portal.Web.Services;

public interface IEmployeeSearchService
{
    Task<IEnumerable<ApplicationUser>> SearchAsync(string? query);
}
