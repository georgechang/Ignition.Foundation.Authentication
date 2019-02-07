using Microsoft.Owin.Security.WsFederation;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;

namespace Ignition.Foundation.Authentication.WsFederation
{
    public class WsFederationIdentityProviderProcessor : IdentityProvidersProcessor
    {
        private readonly string _metadataAddress = Settings.GetSetting("WsFederation.MetadataAddress");
        private readonly string _wtrealm = Settings.GetSetting("WsFederation.Wtrealm");

        public WsFederationIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            //args.App.UseExternalSignInCookie(GetAuthenticationType());

            //args.App.UseCookieAuthentication(
            //    new CookieAuthenticationOptions
            //    {
            //        AuthenticationType = GetAuthenticationType()
            //    });

            var replyUri = new Uri(_wtrealm);

            var options = new WsFederationAuthenticationOptions
            {
                AuthenticationType = IdentityProviderName,
                MetadataAddress = _metadataAddress,
                Wtrealm = _wtrealm,
                Wreply = $"{replyUri.Scheme}{Uri.SchemeDelimiter}{replyUri.Authority}/signin-{IdentityProviderName}",
                Notifications = new WsFederationAuthenticationNotifications
                {
                    SecurityTokenValidated = notification =>
                    {
                        var identityProvider = GetIdentityProvider();
                        notification.AuthenticationTicket.Identity.ApplyClaimsTransformations(new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                        return Task.FromResult(0);
                    }
                }
            };
            args.App.UseWsFederationAuthentication(options);
        }

        protected override string IdentityProviderName => "Federation";
    }
} 
