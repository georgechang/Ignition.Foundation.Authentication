using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Sitecore.Owin.Authentication.Identity;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.Facebook
{
    public class FacebookExternalUserBuilder : DefaultExternalUserBuilder
    {
        public FacebookExternalUserBuilder(bool isPersistentUser) : base(isPersistentUser)
        {
        }

        public FacebookExternalUserBuilder(string isPersistentUser) : base(isPersistentUser)
        {
        }

        public override ApplicationUser BuildUser(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            var identityProvider = FederatedAuthenticationConfiguration.GetIdentityProvider(externalLoginInfo.ExternalIdentity);

            var applicationUser = new ApplicationUser($"{identityProvider.Domain}\\{externalLoginInfo.DefaultUserName}".ToLower()) { IsVirtual = !IsPersistentUser };
            return applicationUser;
        }
    }
}
