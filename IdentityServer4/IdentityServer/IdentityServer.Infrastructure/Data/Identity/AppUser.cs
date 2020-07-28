using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityServer.Infrastructure.Data.Identity
{
    public class AppUser : IdentityUser
    {
        public string FullName { get; set; }
    }
}
