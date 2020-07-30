﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

namespace api
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "API";
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseSerilog((context, configuration) =>
                 {
                     configuration
                         .MinimumLevel.Debug()
                         .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                         .MinimumLevel.Override("System", LogEventLevel.Warning)
                         .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                         .Enrich.FromLogContext()
                         .WriteTo.File(@"identityserver4_log.txt")
                         .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Literate);
                 });
    }
}
