using System.Threading.Tasks;
using Microsoft.Owin.Security.Google;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.Google
{
    public class GoogleIdentityProviderProcessor : IdentityProvidersProcessor
    {
        public GoogleIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            var clientId = Settings.GetSetting("Google.ClientId");
            var clientSecret = Settings.GetSetting("Google.ClientSecret");

            args.App.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                Provider = new GoogleOAuth2AuthenticationProvider
                {
                    OnAuthenticated = context =>
                    {
                        var identityProvider = GetIdentityProvider();
                        foreach (var transformation in identityProvider.Transformations)
                        {
                            transformation.Transform(context.Identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                        }
                        return Task.FromResult(0);
                    }
                }
            });
        }

        protected override string IdentityProviderName => "Google";
    }
} 
