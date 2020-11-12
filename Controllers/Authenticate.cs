using Keove_Case.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Keove_Case.Controllers
{
    [Route("api/user")]
    [ApiController]
    public class Authenticate : ControllerBase
    {
        private IConfiguration _config;

        public Authenticate(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet("authenticate")]
        public IActionResult Login(string username, string password)
        {
            UserModel login = new UserModel();
            login.Id = 1;
            login.Name = "Minel";
            login.UserName = username;
            login.Password = password;
            IActionResult response = Unauthorized();

            UserModel user = null;
            if(login.UserName == "minel" && login.Password == "123")
            {
                user = new UserModel{UserName = "Minel", Password = "123", Id = login.Id, Name = login.Name};
            }


            if(user != null)
            {
                var jwtToken = GenerateJWT(user);
                var refreshToken = GenerateRefreshToken();
                user.RefreshToken = refreshToken;
                response = Ok(new { id = user.Id, name = user.Name, username = user.UserName, jwtToken = jwtToken, refreshToken = refreshToken.Token });

            }
           

            return response;

        }

        [Authorize]
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken(UserModel user, string token, string ipAddress)
        {
            IActionResult response = Unauthorized();
            RefreshToken refreshToken = null;
            if (user.RefreshToken.Token == token)
            {
                refreshToken = user.RefreshToken;
            }
            else
            {
                return null;
            }

            // replace old refresh token with a new one and save
            RefreshToken newRefreshToken = GenerateRefreshToken();
            user.RefreshToken = newRefreshToken;

            // generate new jwt
            var jwtToken = GenerateJWT(user);
            response = Ok(new { id = user.Id, name = user.Name, username = user.UserName, jwtToken = jwtToken, refreshToken = refreshToken.Token });


            return response;
        }
        
        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;
            if(login.UserName == "minel" && login.Password == "123")
            {
                user = new UserModel{UserName = "Minel", Password = "123", Id = login.Id, Name = login.Name};
            }
            return user;
        }

        [Authorize]
        [HttpPost("Post")]
        private string GenerateJWT(UserModel userinfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userinfo.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials
                );

            var encodeToken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodeToken;
        }

        
        private RefreshToken GenerateRefreshToken()
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(7),
                };
            }
        }

    }
}
