using System.Reflection;
//using AuthServer.Infrastructure.Data;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace IdentityServer.Infrastructure.Data.Identity
{
    internal class ConfigurationDbContextFactory : DesignTimeDbContextFactoryBase<ConfigurationDbContext>
    {
        protected override ConfigurationDbContext CreateNewInstance(DbContextOptions<ConfigurationDbContext> options)
        {
            return new ConfigurationDbContext(options, new ConfigurationStoreOptions());
        }
    }
}
