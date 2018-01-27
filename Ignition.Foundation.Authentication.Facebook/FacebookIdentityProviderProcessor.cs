using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Facebook;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;

namespace Ignition.Foundation.Authentication.Processors
{
	public class FacebookIdentityProviderProcessor : IdentityProvidersProcessor
	{
		public FacebookIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
		{
		}

		protected override void ProcessCore(IdentityProvidersArgs args)
		{
			var appId = Settings.GetSetting("Facebook.ApplicationId");
			var appSecret = Settings.GetSetting("Facebook.ApplicationSecret");

			args.App.UseFacebookAuthentication(new FacebookAuthenticationOptions
			{
				AppId = appId,
				AppSecret = appSecret,
				Provider = new FacebookAuthenticationProvider
				{
					OnAuthenticated = context =>
					{
						context.Identity.AddClaim(new Claim("idp", IdentityProviderName));
						return Task.FromResult(0);
					}
				}
			});
		}

		protected override string IdentityProviderName => "Facebook";
	}
}
