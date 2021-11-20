using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System.Net.Http;
using System.Web.Http;

namespace Project.Controllers
{
    public class BaseApiController : ApiController
    {
        private readonly ApplicationUserManager _appUserManager = null;
        private readonly ApplicationRoleManager _appRoleManager = null;
        protected ApplicationUserManager AppUserManager
        {
            get
            {
                return _appUserManager ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        protected ApplicationRoleManager AppRoleManager
        {
            get
            {
                return _appRoleManager ?? Request.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        protected IHttpActionResult GetErrorResult(IdentityResult result)
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
    }
}
