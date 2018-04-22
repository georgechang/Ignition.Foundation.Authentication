using System;
using System.Globalization;
using System.IdentityModel.Tokens;
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
		    var redirectUri = Settings.GetSetting("AzureAD.RedirectUrl");

            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
			{
			    ClientId = clientId,
                Authority = string.Format(CultureInfo.InvariantCulture, aadInstance, "common", "/v2.0 "),
			    Scope = "openid email profile offline_access",
			    RedirectUri = redirectUri,
			    PostLogoutRedirectUri = redirectUri,
			    TokenValidationParameters = new TokenValidationParameters
			    {
			        ValidateIssuer = false,
			    },

			    // The `AuthorizationCodeReceived` notification is used to capture and redeem the authorization_code that the v2.0 endpoint returns to your app.

			    Notifications = new OpenIdConnectAuthenticationNotifications
			    {
                    //AuthenticationFailed = OnAuthenticationFailed,
                    //AuthorizationCodeReceived = OnAuthorizationCodeReceived,
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
