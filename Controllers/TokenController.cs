using HPlusSport.Web.Areas.Identity.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NuGet.Protocol.Core.Types;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static HPlusSport.Web.Areas.Identity.Pages.Account.LoginModel;

namespace HPlusSport.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        //UserManager from Identity to validate Username/Password is valid to generate a token
        private readonly UserManager<HPlusSportWebUser> _userManager;
        private IOptions<SymmetricSecurityOptions> _keyOptions;
        public TokenController(UserManager<HPlusSportWebUser> userManager, IOptions<SymmetricSecurityOptions> keyOptions)
        {
            _userManager = userManager;
            _keyOptions = keyOptions;
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] InputModel model)
        {
            //Check if the user exists
            var user = await _userManager.FindByEmailAsync(model.Email);

            //User doesn't exist or the password does not match
            if(user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                return Unauthorized();
            }

            //User was authorized
            var authClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_keyOptions.Value.Key));

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(authClaims),
                Expires = DateTime.Now.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    key, SecurityAlgorithms.HmacSha512Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(new
            {
                token = tokenHandler.WriteToken(token),
                expires = token.ValidTo
            });
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [Route("Products")]
        public async Task<IActionResult> GetProducts()
        {
            var httpClient = new HttpClient();

            var response = await httpClient.GetAsync("https://localhost:7078/products");
            var data = response.Content.ReadAsStringAsync();

            return Ok(data);
        }
    }
}
