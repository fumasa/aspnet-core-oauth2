using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using JwtOptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Modelos;
using Newtonsoft.Json;

namespace oAuth2.Controllers
{
    [Route("api/jwt")]
    public class JwtController : Controller
    {
        private readonly JwtIssuerOptions _jwtOptions;
        private readonly ILogger _logger;
        private readonly JsonSerializerSettings _serializerSettings;

        public JwtController(IOptions<JwtIssuerOptions> jwtOptions, ILoggerFactory loggerFactory)
        {
            _jwtOptions = jwtOptions.Value;
            ThrowIfInvalidOptions(_jwtOptions);

            _logger = loggerFactory.CreateLogger<JwtController>();

            _serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Get([FromForm] ApplicationUser applicationUser)
        {
            var identity = await GetClaimsIdentity(applicationUser);
            if (identity == null)
            {
                _logger.LogInformation($"Invalid username ({applicationUser.UserName}) or password ({applicationUser.Password})");
                return BadRequest("Invalid credentials");
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, applicationUser.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, await _jwtOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                identity.FindFirst("DisneyCharacter")
            };
            
            var jwt = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims,
                notBefore: _jwtOptions.NotBefore,
                expires: _jwtOptions.Expiration,
                signingCredentials: _jwtOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
            
            var response = new
            {
                access_token = encodedJwt,
                expires_in = (int)_jwtOptions.ValidFor.TotalSeconds
            };

            var json = JsonConvert.SerializeObject(response, _serializerSettings);
            return new OkObjectResult(json);
        }

        private static void ThrowIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator));
            }
        }
        
        private static long ToUnixEpochDate(DateTime date) => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
        
        private static Task<ClaimsIdentity> GetClaimsIdentity(ApplicationUser user)
        {
            if (user.UserName == "MickeyMouse" && user.Password == "MickeyMouseIsBoss123")
            {
                return Task.FromResult(new ClaimsIdentity(
                      new GenericIdentity(user.UserName, "Token"),
                      new[]
                      {
                            new Claim("DisneyCharacter", "IAmMickey")
                      }));
            }

            if (user.UserName == "NotMickeyMouse" && user.Password == "MickeyMouseIsBoss123")
            {
                return Task.FromResult(new ClaimsIdentity(
                    new GenericIdentity(user.UserName, "Token"),
                    new Claim[] { }));
            }
            
            return Task.FromResult<ClaimsIdentity>(null);
        }
    }
}
