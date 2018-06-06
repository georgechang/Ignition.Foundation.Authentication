using System;
using System.IdentityModel.Metadata;
using System.Security.Claims;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Owin;

namespace Ignition.Foundation.Authentication.Saml2
{
	public class Saml2IdentityProviderProcessor : IdentityProvidersProcessor
    {
        private readonly string _spEntityId = Settings.GetSetting("SAML2.ServiceProvider.EntityId");
        private readonly string _spReturnUrl = Settings.GetSetting("SAML2.ServiceProvider.ReturnUrl");
        private readonly string _ipEntityId = Settings.GetSetting("SAML2.IdentityProvider.EntityId");
        private readonly string _ipMetadataLocation = Settings.GetSetting("SAML2.IdentityProvider.MetadataLocation");

        public Saml2IdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            var options = new Saml2AuthenticationOptions(false)
            {
                SPOptions = new SPOptions
                {
                    EntityId = new EntityId(_spEntityId),
                    ReturnUrl = new Uri(_spReturnUrl)
                },
                AuthenticationType = GetAuthenticationType()
            };

            options.IdentityProviders.Add(new Sustainsys.Saml2.IdentityProvider(new EntityId(_ipEntityId), options.SPOptions)
            {
                MetadataLocation = _ipMetadataLocation,
                LoadMetadata = true
            });

            options.Notifications = new Saml2Notifications
            {
                AcsCommandResultCreated = (result, response) =>
                {
                    var identityProvider = GetIdentityProvider();
                    ((ClaimsIdentity)result.Principal.Identity).ApplyClaimsTransformations(new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                }
            };

            args.App.UseSaml2Authentication(options);
        }

        protected override string IdentityProviderName => "saml2";
    }
} 
