using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using DTO;

namespace Project.Controllers
{
    [Authorize]
    public class ProductController : ApiController
    {
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
        public void Post([FromBody]string value)
        {

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
