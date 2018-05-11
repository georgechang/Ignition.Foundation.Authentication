using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.AzureAd
{
	public class AzureAdIdentityProviderProcessor : IdentityProvidersProcessor
	{
	    private readonly string _applicationId = Settings.GetSetting("AzureAD.ApplicationId");
	    private readonly string _tenant = Settings.GetSetting("AzureAD.Tenant");
        private readonly string _aadInstance = Settings.GetSetting("AzureAD.InstanceUrl");
	    private readonly string _redirectUri = Settings.GetSetting("AzureAD.RedirectUrl");

        public AzureAdIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
		{
		}

		protected override void ProcessCore(IdentityProvidersArgs args)
		{
            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
			{
			    ClientId = _applicationId,
                Authority = string.Format(CultureInfo.InvariantCulture, _aadInstance, _tenant),
			    RedirectUri = _redirectUri,
			    PostLogoutRedirectUri = _redirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
			    {
                    //AuthenticationFailed = OnAuthenticationFailed,
                    //AuthorizationCodeReceived = OnAuthorizationCodeReceived,
			        SecurityTokenValidated = context =>
			        {
			            var identityProvider = GetIdentityProvider();
                        context.AuthenticationTicket.Identity.ApplyClaimsTransformations(new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
			            return Task.FromResult(0);
			        }
                }
            });
		}

		protected override string IdentityProviderName => "AzureAD";
	}
}
