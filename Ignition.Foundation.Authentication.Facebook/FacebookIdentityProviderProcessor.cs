using System.Net.Http;
using System.Security.Claims;
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
                Scope = { "email", "user_birthday", "user_location" },
			    BackchannelHttpHandler = new HttpClientHandler(),
			    UserInformationEndpoint = "https://graph.facebook.com/v2.6/me?fields=id,email,first_name,last_name,birthday,gender",
                Provider = new FacebookAuthenticationProvider
				{
					OnAuthenticated = context =>
					{
					    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.User["first_name"] + " " + context.User["last_name"]));
                        context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.User["first_name"].ToString()));
					    context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.User["last_name"].ToString()));
					    context.Identity.AddClaim(new Claim(ClaimTypes.DateOfBirth, context.User["birthday"].ToString()));
					    context.Identity.AddClaim(new Claim(ClaimTypes.Gender, context.User["gender"].ToString()));
					    //context.Identity.AddClaim(new Claim(ClaimTypes.Locality, context.User["hometown"].ToString()));

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
