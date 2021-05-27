using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Okta_SAML_Example.Identity;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace OktaSamlPoc.Controllers
{
    [Route("[controller]/[action]")]
    public class SamlController : Controller
    {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;
        //private const string _logoutCallbackUrl = "/authentication/logout-callback";

        public SamlController(IOptions<Saml2Configuration> configAccessor)
        {
            config = configAccessor.Value;
        }
        //public SamlController(
        //    ISamlServiceProvider samlServiceProvider,
        //    IConfiguration configuration)
        //{
        //    _samlServiceProvider = samlServiceProvider;
        //    _configuration = configuration;
        //}

        //InitiateSingleSignOn
        public IActionResult InitiateSingleSignOn(string returnUrl = null)
        {
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            return binding.Bind(new Saml2AuthnRequest(config)).ToActionResult();
        }

        //public async Task<IActionResult> InitiateSingleSignOn(string returnUrl)
        //{
        //    // To login automatically at the service provider, initiate single sign-on to the identity provider (SP-initiated SSO).            
        //    var partnerName = _configuration["PartnerName"];

        //    await _samlServiceProvider.InitiateSsoAsync(partnerName, returnUrl);

        //    return new EmptyResult();
        //}


        //[HttpPost("Logout")]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> InitiateSingleLogout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);
            return Redirect("~/");
        }
        //public async Task<IActionResult> InitiateSingleLogout(string returnUrl)
        //{


        //    var ssoState = await _samlServiceProvider.GetStatusAsync();

        //    if (await ssoState.CanSloAsync())
        //    {

        //        // Request logout at the identity provider.
        //        await _samlServiceProvider.InitiateSloAsync();

        //        return new EmptyResult();
        //    }
        //    else
        //    {
        //        ClearSessionData();
        //        return Redirect(_logoutCallbackUrl);
        //    }

        //}

        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        //public async Task<IActionResult> AssertionConsumerService()
        //{
        //    // Receive and process the SAML assertion contained in the SAML response.
        //    // The SAML response is received either as part of IdP-initiated or SP-initiated SSO.
        //    var ssoResult = await _samlServiceProvider.ReceiveSsoAsync();

        //    // Create and save a JWT to return when requested.
        //    var jwtSecurityToken = CreateJwtSecurityToken(ssoResult);
        //    HttpContext.Session.SetString("JWT", new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));

        //    // Redirect to the specified URL.
        //    if (!string.IsNullOrEmpty(ssoResult.RelayState))
        //    {
        //        return Redirect(ssoResult.RelayState);
        //    }

        //    return new EmptyResult();
        //}

        //public async Task<IActionResult> SingleLogoutService()
        //{
            

        //    // Receive the single logout request or response.
        //    // If a request is received then single logout is being initiated by the identity provider.
        //    // If a response is received then this is in response to single logout having been initiated by the service provider.
        //    var sloResult = await _samlServiceProvider.ReceiveSloAsync();

        //    if (sloResult.IsResponse)
        //    {
        //        ClearSessionData();
        //        return Redirect(_logoutCallbackUrl);
        //    }
        //    else
        //    {
        //        // Respond to the IdP-initiated SLO request indicating successful logout.
        //        await _samlServiceProvider.SendSloAsync();
        //    }

        //    return new EmptyResult();
        //}

        private void ClearSessionData()
        {
            HttpContext.Session.Remove("JWT");
            
           
                Response.Cookies.Delete(".AspNetCore.Session", new CookieOptions()
                {
                    SameSite=SameSiteMode.Lax
                });
            
        }

        //private JwtSecurityToken CreateJwtSecurityToken(ISpSsoResult ssoResult)
        //{
        //    var claims = new List<Claim>
        //    {
        //        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        //        new Claim(JwtRegisteredClaimNames.Sub, ssoResult.UserID)
        //    };

        //    if (ssoResult.Attributes != null)
        //    {
        //        var samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Email);

        //        if (samlAttribute != null)
        //        {
        //            claims.Add(new Claim(JwtRegisteredClaimNames.Email, samlAttribute.ToString()));
        //        }

        //        samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.GivenName);

        //        if (samlAttribute != null)
        //        {
        //            claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, samlAttribute.ToString()));
        //        }

        //        samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Surname);

        //        if (samlAttribute != null)
        //        {
        //            claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, samlAttribute.ToString()));
        //        }
        //    }

        //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));
        //    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        //    return new JwtSecurityToken(
        //        _configuration["JWT:Issuer"],
        //        _configuration["JWT:Issuer"],
        //        claims,
        //        expires: DateTime.Now.AddHours(1),
        //        signingCredentials: credentials);
        //}
    }
}