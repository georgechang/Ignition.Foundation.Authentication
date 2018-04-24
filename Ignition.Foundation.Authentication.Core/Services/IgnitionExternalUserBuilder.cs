using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Sitecore.Owin.Authentication.Identity;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.Core.Services
{
    public class IgnitionExternalUserBuilder : DefaultExternalUserBuilder
    {
        public IgnitionExternalUserBuilder(bool isPersistentUser) : base(isPersistentUser)
        {
        }

        public IgnitionExternalUserBuilder(string isPersistentUser) : base(isPersistentUser)
        {
        }

        public override ApplicationUser BuildUser(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            var identityProvider = FederatedAuthenticationConfiguration.GetIdentityProvider(externalLoginInfo.ExternalIdentity);

            // this sets the username for the user to be domain\user@domain.com
            var applicationUser = new ApplicationUser($"{identityProvider.Domain}\\{externalLoginInfo.Email}") { IsVirtual = !IsPersistentUser };
            return applicationUser;
        }
    }
}
