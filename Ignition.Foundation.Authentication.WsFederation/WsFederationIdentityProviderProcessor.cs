using System;
using System.IdentityModel.Metadata;
using System.Security.Claims;
using Microsoft.Owin.Security.WsFederation;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;

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
            var options = new WsFederationAuthenticationOptions
            {
                MetadataAddress = _metadataAddress,
                Wtrealm = _wtrealm
            };
            args.App.UseWsFederationAuthentication(options);
        }

        protected override string IdentityProviderName => "wsfed";
    }
} 
