using System;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace Project.Middleware
{
    public class MyCorsMiddleware: OwinMiddleware
    {
        public MyCorsMiddleware(OwinMiddleware next) : base(next)
        {
        }

        public override async Task Invoke(IOwinContext context)
        {
            foreach (var requestHeader in context.Request.Headers)
            {
                Console.WriteLine(requestHeader.Key + @":" +requestHeader.Value);
            }

            await Next.Invoke(context);

            foreach (var responseHeader in context.Response.Headers)
            {
                Console.WriteLine(responseHeader.Key +@":"+responseHeader.Value);
            }
        }
    }
}