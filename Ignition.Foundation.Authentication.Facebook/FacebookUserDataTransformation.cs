using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using Microsoft.Owin.Security.Facebook;
using Sitecore.Owin.Authentication.Services;

namespace Ignition.Foundation.Authentication.Facebook
{
    public class FacebookUserDataTransformation : Transformation
    {
        public override void Transform(ClaimsIdentity identity, TransformationContext context)
        {
            var context = context as FacebookAuthenticatedContext;
            identity.AddClaim(new Claim(ClaimTypes.Name, context.User["first_name"] + " " + context.User["last_name"]));
            identity.AddClaim(new Claim(ClaimTypes.GivenName, context.User["first_name"].ToString()));
            identity.AddClaim(new Claim(ClaimTypes.Surname, context.User["last_name"].ToString()));
            identity.AddClaim(new Claim(ClaimTypes.DateOfBirth, context.User["birthday"].ToString()));
            identity.AddClaim(new Claim(ClaimTypes.Gender, context.User["gender"].ToString()));
        }
    }
}