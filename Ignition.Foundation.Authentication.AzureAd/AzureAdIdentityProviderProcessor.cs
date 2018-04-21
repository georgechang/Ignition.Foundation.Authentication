using System;
using System.Globalization;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.AzureAd
{
	public class AzureAdIdentityProviderProcessor : IdentityProvidersProcessor
	{
		public AzureAdIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
		{
		}

		protected override void ProcessCore(IdentityProvidersArgs args)
		{
			var clientId = Settings.GetSetting("AzureAD.ClientId");
			var aadInstance = Settings.GetSetting("AzureAD.InstanceUrl");
		    var tenant = Settings.GetSetting("AzureAD.TenantName");
		    var postLogoutRedirectUri = Settings.GetSetting("AzureAD.RedirectUrl");

            var authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
			{
			    ClientId = clientId,
			    Authority = authority,
			    PostLogoutRedirectUri = postLogoutRedirectUri,
			    RedirectUri = postLogoutRedirectUri,
			    Notifications = new OpenIdConnectAuthenticationNotifications
			    {
			        SecurityTokenValidated = context =>
			        {
			            var identityProvider = GetIdentityProvider();
			            foreach (var transformation in identityProvider.Transformations)
			            {
			                transformation.Transform(context.AuthenticationTicket.Identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
			            }
                        return Task.FromResult(0);
			        }
			    }
            });
		}

		protected override string IdentityProviderName => "AzureAD";
	}
}
