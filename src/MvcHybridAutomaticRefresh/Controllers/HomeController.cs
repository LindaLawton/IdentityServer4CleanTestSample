using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using Clients;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IdentityModel.AspNetCore;
using Microsoft.AspNetCore.Hosting.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace MvcHybrid.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secure()
        {
            return View();
        }

       

        public static bool isExpired(string token)
        {

            var secret = "secret".Sha256();
            var key = Encoding.ASCII.GetBytes(secret);
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = true
            };
            var claims = handler.ValidateToken(token, validations, out var tokenSecure);
            return true;
        }



        [Authorize]
        public async Task<IActionResult> CallApi()
        {
            //try
            //{
            //var token = await HttpContext.GetTokenAsync("access_token");

            var token = await HttpContext.GetAccessTokenAsync();

            if (isExpired(token)) throw new Exception();

                var client = _httpClientFactory.CreateClient();
                client.SetBearerToken(token);

                var response = await client.GetStringAsync(Constants.SampleApi + "identity");
                ViewBag.Json = JArray.Parse(response).ToString();

                return View();
           // }
           // catch (Exception)
           // {
           ////     return new SignOutResult(new[] { "Cookies", "oidc" });
           // }

            return View();
        }

        public IActionResult Logout()
        {
            return new SignOutResult(new[] { "Cookies", "oidc" });
        }

        public IActionResult Error()
        {
            return View();
        }
    }

    public static class StringExtensions
    {
        public static bool IsMissing(this string value)
        {
            return String.IsNullOrWhiteSpace(value);
        }

        public static string Sha256(this string input)
        {
            if (input.IsMissing()) return String.Empty;

            using (var sha = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hash = sha.ComputeHash(bytes);

                return Convert.ToBase64String(hash);
            }
        }
       

    }

}