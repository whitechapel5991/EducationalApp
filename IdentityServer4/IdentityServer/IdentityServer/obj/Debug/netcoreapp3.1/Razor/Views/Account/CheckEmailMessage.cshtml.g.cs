#pragma checksum "C:\Users\white\source\repos\EducationApp\IdentityServer4\IdentityServer\IdentityServer\Views\Account\CheckEmailMessage.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "51bbcf42fd89d01e7527259cc35e75e7febf49ab"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Account_CheckEmailMessage), @"mvc.1.0.view", @"/Views/Account/CheckEmailMessage.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\white\source\repos\EducationApp\IdentityServer4\IdentityServer\IdentityServer\Views\_ViewImports.cshtml"
using IdentityServer.Models;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"51bbcf42fd89d01e7527259cc35e75e7febf49ab", @"/Views/Account/CheckEmailMessage.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"c53495e5082456cc2504a1a6746484a4e0a4988f", @"/Views/_ViewImports.cshtml")]
    public class Views_Account_CheckEmailMessage : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<CheckEmailMessageViewModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\n<div class=\"row\">\n    Check your email!\n    We\'ve sent an email to ");
#nullable restore
#line 5 "C:\Users\white\source\repos\EducationApp\IdentityServer4\IdentityServer\IdentityServer\Views\Account\CheckEmailMessage.cshtml"
                      Write(Model.Email);

#line default
#line hidden
#nullable disable
            WriteLiteral("\n    Please check your spam folder if you don\'t see our email in your inbox.\n    <a href=\"#\">Need more help?</a>\n</div>\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<CheckEmailMessageViewModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
