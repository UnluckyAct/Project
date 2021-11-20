using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Description;
using System.Web.Http.ModelBinding;
using System.Web.Http.Results;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Project.Models;
using Project.Providers;
using Project.Results;

namespace Project.Controllers
{
    [Authorize]
    [RoutePrefix("api/Account")]
    public class AccountController : BaseApiController
    {
        private const string LocalLoginProvider = "Local";
        

        public AccountController()
        {
        }

        


        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; private set; }

        // GET api/Account/UserInfo
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserInfo")]
        public UserInfoViewModel GetUserInfo()
        {
            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            return new UserInfoViewModel
            {
                Email = User.Identity.GetUserName()
            };
        }

        /// <summary>
        /// Retrieve all users
        /// </summary>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("AllUsers")]
        public List<UserInfo> GetUsers()
        {
            var users = AppUserManager.Users.Where(u=>!u.Deleted);
            List<UserInfo> userInfos = new List<UserInfo>();
            foreach (var user in users)
            {
                userInfos.Add(new UserInfo()
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserType = user.UserType
                });
            }
            return userInfos;
        }

        /// <summary>
        /// Retrieve User by Id
        /// </summary>
        /// <param name="id">user id</param>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [ResponseType(typeof(UserInfo))]
        [Route("Users/{id}")]
        public IHttpActionResult GetUser(string id)
        {

            var appUser = (from applicationUser in AppUserManager.Users
                           where applicationUser.Id == id
                           select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();

            var user = new UserInfo()
            {
                Id = appUser.Id,
                Email = appUser.Email,
                FirstName = appUser.FirstName,
                LastName = appUser.LastName,
                UserType = appUser.UserType
            };
            return Ok(user);
        }

        /// <summary>
        /// Retrieve User by Email
        /// </summary>
        /// <param name="email">User email (username)</param>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [ResponseType(typeof(UserInfo))]
        [Route("Users")]
        [HttpGet]
        public IHttpActionResult GetUserByEmail([FromUri] string email)
        {

            var appUser = (from applicationUser in AppUserManager.Users
                           where applicationUser.Email == email && !applicationUser.Deleted
                           select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();

            var user = new UserInfo()
            {
                Id = appUser.Id,
                Email = appUser.Email,
                FirstName = appUser.FirstName,
                LastName = appUser.LastName,
                UserType = appUser.UserType,
                //Deleted = appUser.Deleted
            };
            return Ok(user);
        }
        /*
        /// <summary>
        /// Delete Admin
        /// </summary>
        /// <param name="email">User email (username)</param>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("AdminUserDelete")]
        [HttpDelete]
        public async Task<IHttpActionResult> DeleteAdminAsync([FromUri] string email)
        {
            var appUser = (from applicationUser in UserManager.Users
                where applicationUser.Email == email
                select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();

            IdentityResult result = await UserManager.DeleteAsync(appUser);
            if (!result.Succeeded)
            {
                return InternalServerError(new Exception(string.Join(";", result.Errors)));
            }
            return StatusCode(HttpStatusCode.NoContent);
        }
        */

        /// <summary>
        /// Delete User 
        /// </summary>
        /// <param name="email">User email (username)</param>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserDelete")]
        [HttpDelete]
        public async Task<IHttpActionResult> DeleteUserAsync([FromUri] string email)
        {
            var appUser = (from applicationUser in AppUserManager.Users
                where applicationUser.Email == email
                select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();

            IdentityResult result = await AppUserManager.DeleteAsync(appUser);
            if (!result.Succeeded)
            {
                return InternalServerError(new Exception(string.Join(";", result.Errors)));
            }
            return StatusCode(HttpStatusCode.NoContent);
        }
        

        /// <summary>
        /// Delete User By Admin
        /// </summary>
        /// <param name="email">User email (username)</param>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("AdminUserDelete")]
        [HttpDelete]
        public async Task<IHttpActionResult> DeleteAdminUserAsync([FromUri] string email)
        {
            var appUser = (from applicationUser in AppUserManager.Users
                where applicationUser.Email == email
                select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();
            appUser.Deleted = true;

            IdentityResult result = await AppUserManager.UpdateAsync(appUser);

            if (!result.Succeeded)
            {
                return InternalServerError();
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        /// <summary>
        /// Update User by User
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UserUpdate")]
        [HttpPatch]
        public async Task<IHttpActionResult> UserUpdate(UserUpdateBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var appUser = (from applicationUser in AppUserManager.Users
                where applicationUser.Email == model.Email
                select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();
            appUser.FirstName = model.FirstName;
            appUser.LastName = model.LastName;
            IdentityResult result = await AppUserManager.UpdateAsync(appUser);
            if (!result.Succeeded)
            {
                return InternalServerError();
            }
            return StatusCode(HttpStatusCode.NoContent);
        }

        /// <summary>
        /// Update User by Admin
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("AdminUpdate")]
        [HttpPatch]
        public async Task<IHttpActionResult> AdminUpdate([FromBody] AdminUpdateBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var appUser = (from applicationUser in AppUserManager.Users
                where applicationUser.Email == model.Email
                select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();

            appUser.FirstName = model.FirstName;
            appUser.LastName = model.LastName;
            appUser.UserType = model.UserType;
            IdentityResult result = await AppUserManager.UpdateAsync(appUser);
            if (!result.Succeeded)
            {
                return InternalServerError();
            }
            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST api/Account/Logout
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return Ok();
        }

        // GET api/Account/ManageInfo?returnUrl=%2F&generateState=true
        [Route("ManageInfo")]
        public async Task<ManageInfoViewModel> GetManageInfo(string returnUrl, bool generateState = false)
        {
            IdentityUser user = await AppUserManager.FindByIdAsync(User.Identity.GetUserId());

            if (user == null)
            {
                return null;
            }

            List<UserLoginInfoViewModel> logins = new List<UserLoginInfoViewModel>();

            foreach (IdentityUserLogin linkedAccount in user.Logins)
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
                ExternalLoginProviders = GetExternalLogins(returnUrl, generateState)
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

            IdentityResult result = await AppUserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword,
                model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        // POST api/Account/SetPassword
        [Route("SetPassword")]
        public async Task<IHttpActionResult> SetPassword(SetPasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await AppUserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);

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

            IdentityResult result = await AppUserManager.AddLoginAsync(User.Identity.GetUserId(),
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
                result = await AppUserManager.RemovePasswordAsync(User.Identity.GetUserId());
            }
            else
            {
                result = await AppUserManager.RemoveLoginAsync(User.Identity.GetUserId(),
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

            ApplicationUser user = await AppUserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

                ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(AppUserManager,
                   OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(AppUserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
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
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(RegisterBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser()
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,           
                UserType = "Bidder"
            };

            IdentityResult result = await AppUserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return StatusCode(HttpStatusCode.NoContent);
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

            IdentityResult result = await AppUserManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            result = await AppUserManager.AddLoginAsync(user.Id, info.Login);
            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            return Ok();
        }

        

        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
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
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
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
