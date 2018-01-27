using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Google;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;

namespace Ignition.Foundation.Authentication.Processors
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
                        context.Identity.AddClaim(new Claim("idp", IdentityProviderName));
                        return Task.FromResult(0);
                    }
                }
            });
        }

        protected override string IdentityProviderName => "Google";
    }
} 
