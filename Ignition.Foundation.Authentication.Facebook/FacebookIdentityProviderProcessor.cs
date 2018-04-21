using System.Threading.Tasks;
using Microsoft.Owin.Security.Facebook;
using Owin;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.Facebook
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

		protected override string IdentityProviderName => "Facebook";
	}
}
