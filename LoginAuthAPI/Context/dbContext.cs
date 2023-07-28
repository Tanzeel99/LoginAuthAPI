using LoginAuthAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace LoginAuthAPI.Context
{
    public class dbContext:DbContext
    {
        public dbContext(DbContextOptions<dbContext> options):base(options)
        {
                
        }

        public DbSet<User> Users { get; set; }
    }
}
