using Common.Interfaces;
using Microsoft.Owin.Security.OAuth;
using Repository;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Web.Http;
using System.Web.Http.Dependencies;
using Unity;
using Unity.Lifetime;
using Unity.WebApi;

namespace Project
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {

            var container = new UnityContainer();

            //var conStr = ConfigurationManager.ConnectionStrings["UserDbConnectionString"].ConnectionString;
            container.RegisterInstance<IProductRepository>(new ProductRepository("UserDbConnectionString"),
                new ContainerControlledLifetimeManager());
            container.RegisterInstance<ICommentRepository>(new ProductRepository("UserDbConnectionString"),
                new ContainerControlledLifetimeManager());
            container.RegisterInstance<IPictureRepository>(new ProductRepository("UserDbConnectionString"),
                new ContainerControlledLifetimeManager());
            container.RegisterInstance<ICategoryRepository>(new ProductRepository("UserDbConnectionString"),
                new ContainerControlledLifetimeManager());
            config.DependencyResolver = new UnityDependencyResolver(container);



            //var cors = new EnableCorsAttribute("*","*","*");
            //config.EnableCors(cors);
            // Web API configuration and services
            // Configure Web API to use only bearer token authentication.
            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }

    //public class UnityResolver : IDependencyResolver
    //{
    //    protected IUnityContainer _container;

    //    public UnityResolver(IUnityContainer container)
    //    {
    //        if (container == null)
    //        {
    //            throw new ArgumentNullException("container");
    //        }

    //        _container = container;
    //    }

    //    public object GetService(Type serviceType)
    //    {
    //        try
    //        {
    //            return _container.Resolve(serviceType);
    //        }
    //        catch (ResolutionFailedException exception)
    //        {
    //            throw new InvalidOperationException("Unable to resolve service for type {" + serviceType + "}.",
    //                exception);
    //        }
    //    }

    //    public IEnumerable<object> GetServices(Type serviceType)
    //    {
    //        try
    //        {
    //            return _container.ResolveAll(serviceType);
    //        }
    //        catch (ResolutionFailedException exception)
    //        {
    //            throw new InvalidOperationException(
    //                "Unable to resolve service for type { " + serviceType + "}.",
    //                exception);
    //        }
    //    }

    //    public IDependencyScope BeginScope()
    //    {
    //        var child = _container.CreateChildContainer();
    //        return new UnityResolver(child);
    //    }

    //    public void Dispose()
    //    {
    //        Dispose(true);
    //    }

    //    protected virtual void Dispose(bool disposing)
    //    {
    //        _container.Dispose();
    //    }
    //}
}
