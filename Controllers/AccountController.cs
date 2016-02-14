using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.ModelBinding;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using AnamnesisServer.Models;
using AnamnesisServer.Providers;
using AnamnesisServer.Results;
using System.Web.Http.Description;
using System.Web.Security;

namespace AnamnesisServer.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : ApiController
    {
        private const string LocalLoginProvider = "Local";
        private ApplicationUserManager _userManager;
        private string modelo = new IdentityUser().GetType().Name;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager,
            ISecureDataFormat<AuthenticationTicket> accessTokenFormat)
        {
            UserManager = userManager;
            AccessTokenFormat = accessTokenFormat;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        [Authorize(Roles = "Admin")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName(),
                HasRegistered = externalLogin == null,
                LoginProvider = externalLogin != null ? externalLogin.LoginProvider : null
            };
        }

        // GET api/Account/RoleUser
        [Route("RoleUser")]
        public IHttpActionResult GetRoleUser()
        {
            ApplicationUser user = UserManager.FindById(User.Identity.GetUserId());
            return Ok(GetUserRole(user));
        }

        // GET api/Account/Users
        [Route("Users")]
        [Authorize(Roles = "Admin")]
        public IEnumerable<FlatUserModel> GetUsers()
        {
            System.Diagnostics.Debug.Write("entra");

            List<FlatUserModel> logins = new List<FlatUserModel>();

            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            ApplicationUser current_user = userManager.FindById(User.Identity.GetUserId());
            if (current_user == null)
            {
                return logins;
            }

            foreach (ApplicationUser user in UserManager.Users)
            {
                String userRoles = GetUserRole(user);
                if (!(UserManager.FindById(user.Id) == UserManager.FindById(current_user.Id)))
                {
                    logins.Add(new FlatUserModel
                    {
                        Id = user.Id,
                        Name = user.Name,
                        LastName = user.LastName,
                        UserName = user.UserName,
                        Email = user.Email,
                        City = user.City,
                        Address = user.Address,
                        Number = user.Number,
                        CreateDate = user.CreateDate,
                        Role = userRoles
                    });
                }
            }

            return logins;
        }

        [Route("Usuarios")]
        [Authorize(Roles = "Admin")]
        public IEnumerable<ShortUserModel> GetUsuarios()
        {
            List<ShortUserModel> logins = new List<ShortUserModel>();

            foreach (ApplicationUser user in UserManager.Users)
            {
                logins.Add(new ShortUserModel
                {
                    UserName = user.UserName
                });
            }

            return logins;
        }

        [Route("Usuarios")]
        [Authorize(Roles = "Admin")]
        [ResponseType(typeof(IEnumerable<ShortUserModel>))]
        public IHttpActionResult GetUsuarios(string value)
        {
            System.Diagnostics.Debug.Write("entra, value: " + value);

            List<ShortUserModel> users = new List<ShortUserModel>();

            if (value == null || value == "")
            {
                foreach (ApplicationUser user in UserManager.Users)
                {
                    users.Add(new ShortUserModel
                    {
                        UserName = user.UserName
                    });
                }
            }
            else
            {
                foreach (ApplicationUser user in UserManager.Users)
                {
                    if (user.UserName.Contains(value))
                    {
                        users.Add(new ShortUserModel
                        {
                            UserName = user.UserName
                        });
                    }
                }
            }

            return Ok(users);
        }

        // GET: api/Account/Users/5
        [Authorize(Roles = "Admin")]
        [ResponseType(typeof(ApplicationUser))]
        [Route("Users")]
        public async Task<IHttpActionResult> GetUsers(string id)
        {
            System.Diagnostics.Debug.Write("entra2");
            var user = await UserManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return Ok(user);
        }

        public String GetUserRole(ApplicationUser user)
        {
            String role = "";
            IList<String> roles = UserManager.GetRoles(user.Id);
            foreach (String obj in roles)
            {
                role += obj;
            }
            return role;

        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {            
            new LogsController().AddLog(LogsController.LOGOUT, modelo);
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            ApplicationUser user =
                await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();
            foreach (ApplicationUserLogin linkedAccount in user.Logins)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = linkedAccount.LoginProvider,
                    ProviderKey = linkedAccount.ProviderKey
                });
            }

            if (user.PasswordHash != null)
            {
                logins.Add(new UserLoginInfoViewModel
                {
                    LoginProvider = LocalLoginProvider,
                    ProviderKey = user.UserName,
                });
            }

            return new ManageInfoViewModel
            {
                LocalLoginProvider = LocalLoginProvider,
                Email = user.UserName,
                Logins = logins,
                //ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
            };
        }

        // POST api/Account/ChangePassword
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        [Authorize(Roles = "Admin")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/AddExternalLogin
        [Route("AddExternalLogin")]
        public async Task<IHttpActionResult> AddExternalLogin(AddExternalLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            AuthenticationTicket ticket = AccessTokenFormat.Unprotect(model.ExternalAccessToken);

            if (ticket == null || ticket.Identity == null || (ticket.Properties != null
                && ticket.Properties.ExpiresUtc.HasValue
                && ticket.Properties.ExpiresUtc.Value < DateTimeOffset.UtcNow))
            {
                return BadRequest("External login failure.");
            }

            ExternalLoginData externalData = ExternalLoginData.FromIdentity(ticket.Identity);

            if (externalData == null)
            {
                return BadRequest("The external login is already associated with an account.");
            }

            IdentityResult result = await UserManager.AddLoginAsync(User.Identity.GetUserId(),
                new UserLoginInfo(externalData.LoginProvider, externalData.ProviderKey));

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }


        // POST api/Account/RemoveLogin
        [Route("RemoveLogin")]
        public async Task<IHttpActionResult> RemoveLogin(RemoveLoginBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result;

            if (model.LoginProvider == LocalLoginProvider)
            {
                result = await UserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(),
                    new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // GET api/Account/ExternalLogin
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            ApplicationUser user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

                ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                   OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName, GetUserRole(user));
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }
            return Ok();
        }

        // GET api/Account/ExternalLogins?returnUrl=%2F&generateState=true
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        // POST api/Account/Register
        [Route("Register")]
        //[AllowAnonymous]
        [Authorize(Roles = "Admin")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            System.Diagnostics.Debug.Write("entra, value: " + model.Email);
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };
            user.Name = model.Name;
            user.LastName = model.LastName;
            user.City = model.City;
            user.Address = model.Address;
            user.Number = model.Number;
            user.CreateDate = DateTime.Now;
            
            IdentityResult result = await UserManager.CreateAsync(user, model.Password);

            // Add user to Role Users if not already added
            var roleManager = HttpContext.Current
                .GetOwinContext().Get<ApplicationRoleManager>();

            var usersRole = roleManager.FindByName("Users");            
            if (model.Role == 2)
            {
                usersRole = roleManager.FindByName("Admin");
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            var userModel = UserManager.FindByName(model.Email);
            var rolesForUser = UserManager.GetRoles(userModel.Id);
            if (!rolesForUser.Contains(usersRole.Name))
            {
                UserManager.AddToRole(userModel.Id, usersRole.Name);
            }
            new LogsController().AddLog(LogsController.CREATE, modelo, userModel);
            return Ok();
        }


        // POST api/Account/EditUser
        [Route("EditUser")]
        //[AllowAnonymous]
        [Authorize(Roles = "Admin")]
        public async Task<IHttpActionResult> EditUser(EditBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            ApplicationUser userModel = await UserManager.FindByIdAsync(model.Id);
            userModel.Email = model.Email;
            userModel.UserName = model.Email;
            userModel.Name = model.Name;
            userModel.LastName = model.LastName;
            userModel.City = model.City;
            userModel.Address = model.Address;
            userModel.Number = model.Number;

            IdentityResult result = await UserManager.UpdateAsync(userModel);

            // Add user to Role Users if not already added
            var roleManager = HttpContext.Current
                .GetOwinContext().Get<ApplicationRoleManager>();

            var usersRole = roleManager.FindByName("Users");
            if (model.Role == 2)
            {
                usersRole = roleManager.FindByName("Admin");
            }

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            
            
            var rolesForUser = UserManager.GetRoles(userModel.Id);
            if (!rolesForUser.Contains(usersRole.Name))
            {
                UserManager.RemoveFromRole(userModel.Id, usersRole.Name);
                UserManager.AddToRole(userModel.Id, usersRole.Name);
            }
            new LogsController().AddLog(LogsController.EDIT, modelo, userModel);
            return Ok();
        }


        // DELETE: api/Account/Delete
        [Route("Delete")]        
        [Authorize(Roles = "Admin")]
        public async Task<IHttpActionResult> PostDelete(DeleteAccountModel model)
        {
            ApplicationUser userModel = UserManager.FindById(model.Id);
            if (userModel == null)
            {
                return NotFound();
            }            

            new LogsController().AddLog(LogsController.DELETE, modelo, userModel);

            await UserManager.DeleteAsync(userModel);         
            return Ok();
        }

        // POST api/Account/RegisterExternal
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("RegisterExternal")]
        public async Task<IHttpActionResult> RegisterExternal(RegisterExternalBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var info = await Authentication.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return InternalServerError();
            }

            var user = new ApplicationUser() { UserName = model.Email, Email = model.Email };

            IdentityResult result = await UserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await UserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            return Ok();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }

       

        #region Aplicaciones auxiliares

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IHttpActionResult GetErrorResult(IdentityResult result)
        {
            if (result == null)
            {
                return InternalServerError();
            }

            if (!result.Succeeded)
            {
                if (result.Errors != null)
                {
                    foreach (string error in result.Errors)
                    {
                        ModelState.AddModelError("", error);
                    }
                }

                if (ModelState.IsValid)
                {
                    // No ModelState errors are available to send, so just return an empty BadRequest.
                    return BadRequest();
                }

                return BadRequest(ModelState);
            }

            return null;
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits debe ser uniformemente divisible por 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        #endregion
    }
}
