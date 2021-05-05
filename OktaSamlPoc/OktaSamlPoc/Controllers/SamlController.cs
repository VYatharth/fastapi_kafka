using ComponentSpace.Saml2;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OktaSamlPoc.Controllers
{
    [Route("[controller]/[action]")]
    public class SamlController : Controller
    {
        private readonly ISamlServiceProvider _samlServiceProvider;
        private readonly IConfiguration _configuration;

        public SamlController(
            ISamlServiceProvider samlServiceProvider,
            IConfiguration configuration)
        {
            _samlServiceProvider = samlServiceProvider;
            _configuration = configuration;
        }

        public async Task<IActionResult> InitiateSingleSignOn(string returnUrl)
        {
            // To login automatically at the service provider, initiate single sign-on to the identity provider (SP-initiated SSO).            
            var partnerName = _configuration["PartnerName"];

            await _samlServiceProvider.InitiateSsoAsync(partnerName, returnUrl);

            return new EmptyResult();
        }

        public async Task<IActionResult> InitiateSingleLogout(string returnUrl)
        {
            // Remove the JWT.
            HttpContext.Session.Remove("JWT");

            var ssoState = await _samlServiceProvider.GetStatusAsync();

            if (await ssoState.CanSloAsync())
            {
                // Request logout at the identity provider.
                await _samlServiceProvider.InitiateSloAsync(relayState: returnUrl);

                return new EmptyResult();
            }

            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return new EmptyResult();
        }

        public async Task<IActionResult> AssertionConsumerService()
        {
            // Receive and process the SAML assertion contained in the SAML response.
            // The SAML response is received either as part of IdP-initiated or SP-initiated SSO.
            var ssoResult = await _samlServiceProvider.ReceiveSsoAsync();

            // Create and save a JWT to return when requested.
            var jwtSecurityToken = CreateJwtSecurityToken(ssoResult);
            HttpContext.Session.SetString("JWT", new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken));

            // Redirect to the specified URL.
            if (!string.IsNullOrEmpty(ssoResult.RelayState))
            {
                return Redirect(ssoResult.RelayState);
            }

            return new EmptyResult();
        }

        public async Task<IActionResult> SingleLogoutService()
        {
            // Remove the JWT.
            HttpContext.Session.Remove("JWT");

            // Receive the single logout request or response.
            // If a request is received then single logout is being initiated by the identity provider.
            // If a response is received then this is in response to single logout having been initiated by the service provider.
            var sloResult = await _samlServiceProvider.ReceiveSloAsync();

            if (sloResult.IsResponse)
            {
                // SP-initiated SLO has completed.
                if (!string.IsNullOrEmpty(sloResult.RelayState))
                {
                    return Redirect(sloResult.RelayState);
                }
            }
            else
            {
                // Respond to the IdP-initiated SLO request indicating successful logout.
                await _samlServiceProvider.SendSloAsync();
            }

            return new EmptyResult();
        }

        private JwtSecurityToken CreateJwtSecurityToken(ISpSsoResult ssoResult)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, ssoResult.UserID)
            };

            if (ssoResult.Attributes != null)
            {
                var samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Email);

                if (samlAttribute != null)
                {
                    claims.Add(new Claim(JwtRegisteredClaimNames.Email, samlAttribute.ToString()));
                }

                samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.GivenName);

                if (samlAttribute != null)
                {
                    claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, samlAttribute.ToString()));
                }

                samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Surname);

                if (samlAttribute != null)
                {
                    claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, samlAttribute.ToString()));
                }
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityToken(
                _configuration["JWT:Issuer"],
                _configuration["JWT:Issuer"],
                claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);
        }
    }
}