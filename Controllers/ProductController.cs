using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Common.Interfaces;
using DTO;
using Microsoft.AspNet.Identity;

namespace Project.Controllers
{
    [Authorize]
    public class ProductController : ApiController
    {
        private IProductRepository _repoPR;
        private ICommentRepository _repoCO;
        private ICategoryRepository _repoCA;
        private IPictureRepository _repoPI;
        public ProductController(IProductRepository repoPR, ICommentRepository repoCO, ICategoryRepository repoCA, IPictureRepository repoPI)
        {
            _repoPR = repoPR;
            _repoCO = repoCO;
            _repoCA = repoCA;
            _repoPI = repoPI;
        }
        // GET api/values
        public List<string> Get(int id)
        {
            return new List<string> { "ProductNama", "Seller", "Bidder", "Bid", "StartDate", "EndDate", "Description", "Picture" };
        }

        // GET api/values/5
        /*public string Get(int id)
        {
            return "value";
        }*/

        // POST api/values
        [Authorize(Roles = "Administrator, User Manager, User")]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalBearer)]
        [HttpPost]
        public void CreateProduct([FromBody]Product value)
        {
            _repoPR.CreateProduct(value);
        }

        // PUT api/values/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        public void Delete(int id)
        {
        }
    }
}
