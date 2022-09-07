using HPlusSport.Web.Areas.Identity.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Protocol.Core.Types;
using static HPlusSport.Web.Areas.Identity.Pages.Account.LoginModel;

namespace HPlusSport.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        //UserManager from Identity to validate Username/Password is valid to generate a token
        private readonly UserManager<HPlusSportWebUser> _userManager;
        public TokenController(UserManager<HPlusSportWebUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] InputModel model)
        {
            //Check if the user exists
            var user = await _userManager.FindByEmailAsync(model.Email);

            //User doesn't exist or the password does not match
            if(user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                return Unauthorized(user);
            }
        }
    }
}
