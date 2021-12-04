using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Project.Models;

namespace Project.Controllers
{
    [Authorize]
    [RoutePrefix("api/Roles")]
    public class RolesController : BaseApiController
    {

        [Authorize(Roles = "Administrator")]
        [Route("GetAllRoles")]
        public async Task<IHttpActionResult> GetRole([FromBody] string Id)
        {
            var role = await this.AppRoleManager.FindByIdAsync(Id);

            if (role != null)
            {
                return Ok(role);
            }

            return NotFound();

        }

        [Authorize(Roles = "Administrator")]
        [Route("GetRoles")]
        public IHttpActionResult GetAllRoles()
        {
            var roles = this.AppRoleManager.Roles.Select(r=>r.Name);
           
            return Ok(roles);
        }

        [Authorize(Roles = "Administrator")]
        [Route("Create")]
        public async Task<IHttpActionResult> Create(CreateRoleBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var role = new IdentityRole { Name = model.Name };

            var result = await this.AppRoleManager.CreateAsync(role);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            Uri locationHeader = new Uri(Url.Link("GetRoleById", new { id = role.Id }));

            return Created(locationHeader, role);

        }

        [Authorize(Roles = "Administrator")]
        [Route("Delete")]
        public async Task<IHttpActionResult> DeleteRole(string Id)
        {

            var role = await this.AppRoleManager.FindByIdAsync(Id);

            if (role != null)
            {
                IdentityResult result = await this.AppRoleManager.DeleteAsync(role);

                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }

                return Ok();
            }

            return NotFound();

        }
    }
}
