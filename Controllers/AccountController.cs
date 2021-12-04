using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
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
using Microsoft.Ajax.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Project.Models;
using Project.Providers;
using Project.Results;
using Expression = System.Linq.Expressions.Expression;

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


        /// <summary>
        /// Retrieve all users
        /// </summary>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, User Manager")]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("AllUsers")]
        [HttpGet]
        public async Task<IHttpActionResult> GetUsersAsync([FromUri] int pageNumber, int pageSize, string orderBy)
        {
            var t = AppUserManager.Users.Where(u => !u.Deleted);

            int count = AppUserManager.Users.Count(u => !u.Deleted);
            int pages = count / pageSize;
            if (count == 0)
                return NotFound();

            if (count % pageSize != 0)
            {
                if (pages == 0)
                    pageSize = count;
                pages += 1;
            }

            var users = GetOrderExpression(t, orderBy).Skip((pageNumber - 1) * pageSize).Take(pageSize).ToList();

            List<UserInfo> userInfos = new List<UserInfo>();
            foreach (var user in users)
            {
                userInfos.Add(new UserInfo()
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserType = user.UserType,
                    Roles = (await AppUserManager.GetRolesAsync(user.Id)).ToArray(),
                    JoinDate = user.JoinDate.ToUniversalTime()
                });
            }

            var userTable = new UserTable()
            {
                UsersList = userInfos,
                Pages = pages
            };

            return Ok(userTable);
        }

        [Authorize(Roles = "Administrator")]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("GetBannedUsers")]
        [HttpGet]
        public async Task<IHttpActionResult> GetBannedUsersAsync([FromUri] int pageNumber, int pageSize, string orderBy)
        {
            Console.WriteLine(pageNumber);
            var t = AppUserManager.Users.Where(u => u.Deleted);
            int count = AppUserManager.Users.Count(u => u.Deleted) / pageSize;
            if (count == 0)
                return NotFound();
            if (count % pageSize != 0)
            {
                count += 1;
            }
            var users = GetOrderExpression(t, orderBy).Skip((pageNumber - 1) * pageSize).Take(pageSize).ToList();

            List<UserInfo> userInfos = new List<UserInfo>();
            foreach (var user in users)
            {
                userInfos.Add(new UserInfo()
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserType = user.UserType,
                    Roles = (await AppUserManager.GetRolesAsync(user.Id)).ToArray(),
                    JoinDate = user.JoinDate.ToUniversalTime()
                });
            }

            var userTable = new UserTable()
            {
                UsersList = userInfos,
                Pages = count
            };

            return Ok(userTable);
        }

        /// <summary>
        /// Unban User
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("UnbanUser")]
        [HttpPatch]
        public async Task<IHttpActionResult> UserUnban([FromUri] string email)
        {
            var appUser = (from applicationUser in AppUserManager.Users
                where applicationUser.Email == email
                select applicationUser).SingleOrDefault();
            if (appUser == null)
            {
                return NotFound();
            }

            appUser.Deleted = false;
            IdentityResult result = await AppUserManager.UpdateAsync(appUser);

            if (!result.Succeeded)
            {
                return InternalServerError();
            }

            string[] rolesToAssign = new string[1];
            rolesToAssign[0] = "User";

            IdentityResult addResult = await this.AppUserManager.AddToRolesAsync(appUser.Id, rolesToAssign);

            if (!addResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to add user");
                IdentityResult result2 = await AppUserManager.DeleteAsync(appUser);
                return BadRequest(ModelState);
            }
            return StatusCode(HttpStatusCode.NoContent);
        }

        /// <summary>
        /// Retrieve User by Id
        /// </summary>
        /// <param name="id">user id</param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, User Manager")]
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
        [Authorize(Roles = "Administrator, User Manager, User")]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [ResponseType(typeof(UserInfo))]
        [Route("Users")]
        [HttpGet]
        public async Task<IHttpActionResult> GetUserByEmailAsync([FromUri] string email)
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
                Roles = (await AppUserManager.GetRolesAsync(appUser.Id)).ToArray(),
                JoinDate = appUser.JoinDate.ToUniversalTime()
            };
            return Ok(user);
        }
        /// <summary>
        /// Delete User 
        /// </summary>
        /// <param name="email">User email (username)</param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, Manager, User")]
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

            var currentRoles = await this.AppUserManager.GetRolesAsync(appUser.Id);
            IdentityResult removeResult = await this.AppUserManager.RemoveFromRolesAsync(appUser.Id, currentRoles.ToArray());
            if (!removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to Delete user roles");
                return BadRequest(ModelState);
            }

            return StatusCode(HttpStatusCode.NoContent);
        }


        /// <summary>
        /// Delete User By Admin
        /// </summary>
        /// <param name="email">User email (username)</param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, User Manager")]
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

            var currentRoles = await this.AppUserManager.GetRolesAsync(appUser.Id);
            IdentityResult removeResult = await this.AppUserManager.RemoveFromRolesAsync(appUser.Id, currentRoles.ToArray());
            if (!removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to Delete user roles");
                return BadRequest(ModelState);
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        /// <summary>
        /// Update User by User
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, Manager, User")]
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
        [Authorize(Roles = "Administrator, User Manager")]
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
        [Authorize(Roles = "Administrator, User Manager, User")]
        [Route("Logout")]
        public IHttpActionResult Logout()
        {
            Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            return StatusCode(HttpStatusCode.NoContent);
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
                UserType = "Bidder",
                JoinDate = DateTime.UtcNow
            };

            IdentityResult result = await AppUserManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }
            else
            {                
                var appUser = (from applicationUser in AppUserManager.Users
                               where applicationUser.Email == user.Email
                               select applicationUser).SingleOrDefault();
                if (appUser == null)
                    return NotFound();

                string[] rolesToAssign = new string[1];
                rolesToAssign[0] = "User";

                IdentityResult addResult = await this.AppUserManager.AddToRolesAsync(appUser.Id, rolesToAssign);

                if (!addResult.Succeeded)
                {
                    ModelState.AddModelError("", "Failed to add user roles");
                    IdentityResult result2 = await AppUserManager.DeleteAsync(appUser);
                    return BadRequest(ModelState);
                }
                return StatusCode(HttpStatusCode.NoContent);
            }
        }

        /// <summary>
        /// Assign Roles
        /// </summary>
        /// <param name="email"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator")]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("AssignRoles")]
        [HttpPut]
        public async Task<IHttpActionResult> AssignRolesToUser([FromUri] string email, [FromBody] RolesModel model)
        {
            string[] rolesToAdd = model.Roles;
            List<string> rolesToAssign = new List<string>();
            bool hasManager = false;
            bool needsManager = false;
            foreach (var role in rolesToAdd)
            {
                if (role == "User Manager" || role == "Product Manager")
                    needsManager = true;
                if (role == "Manager")
                    hasManager = true;
                rolesToAssign.Add(role);
            }
            if (!hasManager && needsManager)
                rolesToAssign.Add("Manager");
            else if (hasManager && !needsManager)
            {
                rolesToAssign.Add("User Manager");
                rolesToAssign.Add("Product Manager");
            }

            var appUser = (from applicationUser in AppUserManager.Users
                           where applicationUser.Email == email
                           select applicationUser).SingleOrDefault();

            if (appUser == null)
            {
                return NotFound();
            }
            
            var currentRoles = await this.AppUserManager.GetRolesAsync(appUser.Id);
            
            var rolesNotExists = rolesToAssign.Except(this.AppRoleManager.Roles.Select(x => x.Name)).ToArray();

            if (rolesNotExists.Count() > 0)
            {
                ModelState.AddModelError("", string.Format("Roles '{0}' does not exixts in the system", string.Join(",", rolesNotExists)));
                return BadRequest(ModelState);
            }

            IdentityResult removeResult = await this.AppUserManager.RemoveFromRolesAsync(appUser.Id, currentRoles.ToArray());

            if (!removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to remove user roles");
                return BadRequest(ModelState);
            }

            IdentityResult addResult = await this.AppUserManager.AddToRolesAsync(appUser.Id, rolesToAssign.ToArray());

            if (!addResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to add user roles");
                return BadRequest(ModelState);
            }

            return Ok();

        }

        /// <summary>
        /// Retrieve Users Roles
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Authorize(Roles = "Administrator, User Manager, User")]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [Route("GetUserRoles")]
        [HttpGet]
        public async Task<IHttpActionResult> GetUserRoles([FromUri] string email)
        {
            var appUser = (from applicationUser in AppUserManager.Users
                           where applicationUser.Email == email
                           select applicationUser).SingleOrDefault();

            if (appUser == null)
                return NotFound();

            var currentRoles = await this.AppUserManager.GetRolesAsync(appUser.Id);

            if (currentRoles == null)
            {
                ModelState.AddModelError("", "User Has No Roles");
                return BadRequest(ModelState);
            }

            return Ok(currentRoles);
        }
        #region Helpers

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        private IOrderedQueryable<ApplicationUser> GetOrderExpression(IQueryable<ApplicationUser>user, string orderBy)
        {
            IOrderedQueryable<ApplicationUser> v;
            switch (orderBy)
            {
                case "Email":
                    v = user.OrderBy(u => u.Email);
                    break;
                case "JoinDate":
                    v = user.OrderBy(u => u.JoinDate);
                    break;
                case "FirstName":
                    v = user.OrderBy(u => u.FirstName);
                    break;
                case "LastName":
                    v = user.OrderBy(u => u.LastName);
                    break;
                case "UserType":
                    v = user.OrderBy(u => u.UserType);
                    break;
                default:
                    v = user.OrderBy(u => u.Id);
                    break;
            }

            return v;
        }

        #endregion
    }
}
