using System.Security.Claims;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.Core.Transformations
{
    public class AddIdpClaimTransformation : Transformation
    {
        public override void Transform(ClaimsIdentity identity, TransformationContext context)
        {
            identity.AddClaim(new Claim("idp", context.IdentityProvider.Name));
        }
    }
}
