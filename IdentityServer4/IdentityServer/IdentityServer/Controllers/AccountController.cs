using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using IdentityServer.Extensions;
using IdentityServer.Infrastructure.Constants;
using IdentityServer.Infrastructure.Data.Identity;
using IdentityServer.Models;
using IdentityServer.Models.Base;
using IdentityServer.Models.Settings;
using IdentityServer.Services;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IClientStore _clientStore;
        private readonly IEventService _events;
        private readonly EmailService _emailService;

        public AccountController(SignInManager<AppUser> signInManager, 
            UserManager<AppUser> userManager, 
            IIdentityServerInteractionService interaction, 
            IAuthenticationSchemeProvider schemeProvider, 
            IClientStore clientStore, 
            IEventService events,
            EmailService emailService)
        {
            _userManager = userManager;
            _interaction = interaction;
            _schemeProvider = schemeProvider;
            _clientStore = clientStore;
            _events = events;
            _emailService = emailService;
            _signInManager = signInManager;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildViewModelWithExternalProvidersAsync<LoginViewModel>(returnUrl);

            //if (vm.IsExternalLoginOnly)
            //{
            //    // we only have one option for logging in and it's an external provider
            //    return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            //}

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (await _clientStore.IsPkceClientAsync(context.Client.ClientId))
                    {
                        // if the client is PKCE then we assume it's native, so this change in how to
                        // return the response is for better UX for the end user.
                        return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                // validate username/password
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                    // only set explicit expiration here if user chooses "remember me". 
                    // otherwise we rely upon expiration configured in cookie middleware.
                    AuthenticationProperties props = null;
                    if (model.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                        };
                    };

                    // issue authentication cookie with subject ID and username
                    var isuser = new IdentityServerUser(user.Id)
                    {
                        DisplayName = user.UserName
                    };

                    // issue authentication cookie with subject ID and username
                    await HttpContext.SignInAsync(isuser, props);

                    if (context != null)
                    {
                        if (await _clientStore.IsPkceClientAsync(context.Client.ClientId))
                        {
                            // if the client is PKCE then we assume it's native, so this change in how to
                            // return the response is for better UX for the end user.
                            return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Email, "invalid credentials"));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ForgotPassword(string returnUrl)
        {
            //var vm = await BuildLoginViewModelAsync(returnUrl);

            return View(new ForgotPasswordViewModel() { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // validate username/password
                var user = await _userManager.FindByEmailAsync(model.Email);

                if(user == null)
                {
                    ModelState.AddModelError(string.Empty, AccountOptions.EmailNotFoundErrorMessage);
                }
                else
                {
                    // send email....
                    return RedirectToAction("CheckEmailMessage", new { email = model.Email, });
                }
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> CheckEmailMessage(string email)
        {
            return View(new CheckEmailMessageViewModel() { Email = email });
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Register(string returnUrl)
        {
            // build a model so we know what to show on the login page
            //var vm = await BuildLoginViewModelAsync(returnUrl);
            var vm = await BuildViewModelWithExternalProvidersAsync<RegisterViewModel>(returnUrl);

            //if (vm.IsExternalLoginOnly)
            //{
            //    // we only have one option for logging in and it's an external provider
            //    return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            //}

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            //var aVal = 0; var blowUp = 1 / aVal;

            var userWithThisEmail = await _userManager.FindByEmailAsync(model.Email);

            if (userWithThisEmail != null)
            {
                ModelState.AddModelError("", "Email already registred");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            string CreateUserName(string fullName)
            {
                var userName = fullName.Trim().Split(' ');
                string resultUserName = string.Empty;

                foreach (var item in userName)
                {
                    resultUserName += item;
                }

                return resultUserName;
            }

            var user = new AppUser { UserName = CreateUserName(model.FullName), FullName = model.FullName, Email = model.Email };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, $"{error.Code}: {error.Description}");
                }
                
                return View(model);
            }

            await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("fullName", user.FullName));
            await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("userName", user.UserName));
            await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("email", user.Email));

            var role = model.IsTeacher ? Roles.Teacher : Roles.Student;
            await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("role", role));

            // генерация токена для пользователя
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Action(
                "ConfirmEmail",
                "Account",
                new { userId = user.Id, code = code },
                protocol: HttpContext.Request.Scheme);
            //EmailService emailService = new EmailService();
            await _emailService.SendEmailAsync(model.Email, "Confirm your account",
                $"Подтвердите регистрацию, перейдя по ссылке: <a href='{callbackUrl}'>link</a>");

            return Content("Для завершения регистрации проверьте электронную почту и перейдите по ссылке, указанной в письме");

            //return Ok(new RegisterResponseViewModel(user));
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("Error");
            }
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
                return RedirectToAction("Index", "Home");
            else
                return View("Error");
        }

        [HttpGet]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(string logoutId)
        {
            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);

            if (context.PostLogoutRedirectUri != null)
            {
                return Redirect(context.PostLogoutRedirectUri);
            }

            return Redirect("~/");
        }

        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginViewModel model)
        {
            var vm = await BuildViewModelWithExternalProvidersAsync<LoginViewModel>(model.ReturnUrl);
            vm.Email = model.Email;
            vm.RememberLogin = model.RememberLogin;
            vm.Password = model.Password;
            return vm;
        }

        private async Task<RegisterViewModel> BuildRegisterViewModelAsync(RegisterViewModel model)
        {
            var vm = await BuildViewModelWithExternalProvidersAsync<RegisterViewModel>(model.ReturnUrl);
            vm.Email = model.Email;
            vm.FullName = model.FullName;
            vm.IsTeacher = model.IsTeacher;
            vm.Password = model.Password;
            return vm;
        }

        private async Task<TClass> BuildViewModelWithExternalProvidersAsync<TClass>(string returnUrl) 
            where TClass : WithExternalProvider, new()
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new TClass
                {
                    ReturnUrl = returnUrl,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                 .Where(x => x.DisplayName != null)
                 .Select(x => new ExternalProvider
                 {
                     DisplayName = x.DisplayName ?? x.Name,
                     AuthenticationScheme = x.Name
                 }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new TClass
            {
                //AllowRememberLogin = AccountOptions.AllowRememberLogin,
                //EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                //Email = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }
    }
}
