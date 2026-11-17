using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class LogDetectorContext(DbContextOptions<LogDetectorContext> options) : IdentityDbContext<LogDetector.Models.ApplicationUser>(options)
{
}
