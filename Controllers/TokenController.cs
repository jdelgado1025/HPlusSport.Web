using HPlusSport.Web.Areas.Identity.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Protocol.Core.Types;

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
    }
}
