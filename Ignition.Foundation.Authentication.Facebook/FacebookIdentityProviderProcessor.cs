using System.Threading.Tasks;
using Microsoft.Owin.Security.Facebook;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.Facebook
{
	public class FacebookIdentityProviderProcessor : IdentityProvidersProcessor
	{
        private readonly string _appId = Settings.GetSetting("Facebook.ApplicationId");
        private readonly string _appSecret = Settings.GetSetting("Facebook.ApplicationSecret");

        public FacebookIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
		{
		}

		protected override void ProcessCore(IdentityProvidersArgs args)
		{
			args.App.UseFacebookAuthentication(new FacebookAuthenticationOptions
			{
				AppId = _appId,
				AppSecret = _appSecret,
				Provider = new FacebookAuthenticationProvider
				{
					OnAuthenticated = context =>
					{
					    var identityProvider = GetIdentityProvider();
                        context.Identity.ApplyClaimsTransformations(new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
			            return Task.FromResult(0);
					}
				}
			});
		}

		protected override string IdentityProviderName => "Facebook";
	}
}
