using System;
using System.IdentityModel.Metadata;
using Ignition.Foundation.Authentication.Core.Managers;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Owin;

namespace Ignition.Foundation.Authentication.Saml2
{
	public class Saml2IdentityProviderProcessor : IdentityProvidersProcessor
    {
        public Saml2IdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            var spEntityId = Settings.GetSetting("SAML2.ServiceProvider.EntityId");
            var spReturnUrl = Settings.GetSetting("SAML2.ServiceProvider.ReturnUrl");

            var ipEntityId = Settings.GetSetting("SAML2.IdentityProvider.EntityId");
            var ipMetadataLocation = Settings.GetSetting("SAML2.IdentityProvider.MetadataLocation");

            var options = new Saml2AuthenticationOptions(false)
            {
                SPOptions = new SPOptions
                {
                    EntityId = new EntityId(spEntityId),
                    ReturnUrl = new Uri(spReturnUrl)
                },
                AuthenticationType = GetAuthenticationType()
            };

            options.SPOptions.SystemIdentityModelIdentityConfiguration.ClaimsAuthenticationManager = new SitecoreClaimsAuthenticationManager(IdentityProviderName);
            options.IdentityProviders.Add(new Sustainsys.Saml2.IdentityProvider(new EntityId(ipEntityId), options.SPOptions)
            {
                MetadataLocation = ipMetadataLocation,
                LoadMetadata = true
            });

            args.App.UseSaml2Authentication(options);
        }

        protected override string IdentityProviderName => "saml2";
    }
} 
