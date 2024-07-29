using DE2.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace DE2.Controllers
{
    public class NguoiDungController : Controller
    {
        DE2Entities db = new DE2Entities();
        // GET: NguoiDung

        public bool checkToken()
        {
            var access_token = Session["access_token"];
            if (access_token == null)
            {
                return false;
            }
            else
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(Convert.ToString(ConfigurationManager.AppSettings["config:JwtKey"]));
                tokenHandler.ValidateToken(access_token.ToString(), new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero

                }, out SecurityToken validatedToken);

                // Corrected access to the validatedToken
                var jwtToken = (JwtSecurityToken)validatedToken;
                if (jwtToken.ValidTo < DateTime.UtcNow)
                {

                    return false;
                }


            }
            return true;
        }
        public ActionResult Index()
        {
            //bool check = checkToken();
            //if (!check)
            //{
            //    return RedirectToAction("Login");
            //}
            List<TinTuc> list = db.TinTucs.Where(x => x.IsDelete == false).OrderByDescending(n =>n.NgayDang).ToList();
            return View(list);
        }
        
        public ActionResult LogOut()
        {

            Session["Login"] = null;
            return RedirectToAction("Login", "Home");
        }

        public ActionResult Details(int? id)
        {
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            TinTuc tin = db.TinTucs.Find(id);
            if (tin == null)
            {
                return HttpNotFound();
            }
            return View(tin);
        }
       
    }
}