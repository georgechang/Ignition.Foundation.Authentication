using System.Security.Claims;

namespace Ignition.Foundation.Authentication.Core.Managers
{
    public class SitecoreClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        private readonly string _identityProviderName;

        public SitecoreClaimsAuthenticationManager(string identityProviderName)
        {
            _identityProviderName = identityProviderName;
        }

        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            if (incomingPrincipal != null && incomingPrincipal.Identity.IsAuthenticated)
            {
                // this adds an additional claim called "idp" that matches the identity provider name as specified in the Sitecore OWIN configuration
                ((ClaimsIdentity)incomingPrincipal.Identity).AddClaim(new Claim("idp", _identityProviderName));
            }

            return incomingPrincipal;
        }
    }
}
