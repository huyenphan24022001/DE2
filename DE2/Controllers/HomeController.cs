using DE2.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace DE2.Controllers
{
    public class HomeController : Controller
    {
        
        DE2Entities db = new DE2Entities();
        public ActionResult Index()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }

            List<TinTuc> list = db.TinTucs.Where(x => x.IsDelete == false).ToList();
            return View(list);
        }
        public ActionResult Login()
        {
            return View();
        }
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
        public ActionResult LogOut()
        {
            Session["Login"] = null;
            return View("Login");
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Login user)
        {
            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["config:JwtKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            string hashedPassword = HashPassword(user.Password, "12345!#aB");

            User u = db.Users.FirstOrDefault(x => x.UserName == user.UserName && x.Pass == hashedPassword && x.Role == 1);


            if (u != null)
            {
                var claims = new[]
        { new Claim("ID", u.ID.ToString()),
                    new Claim("UserName", u.UserName),
                    new Claim("Role", u.Role.ToString())
                    // Add more claims if needed
                };

                var accessToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1), // Token expires in 1 hour
                    signingCredentials: credentials
                );

                var refreshToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddDays(7), // Token expires in 7day
                    signingCredentials: credentials
                );
                var access_token = new JwtSecurityTokenHandler().WriteToken(accessToken);
                var refresh_token = new JwtSecurityTokenHandler().WriteToken(refreshToken);
                Models.Token to = new Models.Token()
                {
                    Users_ID = u.ID,
                    access_token = access_token,
                    refresh_token = refresh_token,
                };
                db.Tokens.Add(to);
                db.SaveChanges();

                Session["access_token"] = access_token;
                //Session["refresh_token"] = refresh_token;
                Session["Login"] = true;
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("", "Login data is incorrect!");
            }
            return View();
        }

        public ActionResult Create()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }

            return View();
        }

        public ActionResult Error(string MaError)
        {
            ViewBag.Error = MaError;
            return View();
        }

        public ActionResult Success(string Success)
        {
            ViewBag.Success = Success;
            return View();
        }

        [HttpPost]
        public ActionResult Create(FormCollection collection, TinTuc tintuc, HttpPostedFileBase HinhAnh)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }

            try
            {
                if (HinhAnh != null && HinhAnh.ContentLength > 0)
                {
                    //Get file name
                    var fileName = Path.GetFileName(HinhAnh.FileName);
                    //Get path
                    var path = Path.Combine(Server.MapPath("~/Content/images"), fileName);

                    //Check exitst
                    if (!System.IO.File.Exists(path))
                    {
                        //Add image into folder
                        HinhAnh.SaveAs(path);



                    }
                    tintuc.NgayDang = DateTime.Now;
                    tintuc.HinhAnh = HinhAnh.FileName;
                    tintuc.IsDelete = false;
                    db.TinTucs.Add(tintuc);
                    db.SaveChanges();
                    return RedirectToAction("Success", "Home", new { Success = "Thêm tin tức thành công" });


                }
                else
                {
                    return RedirectToAction("Error", "Home", new { @MaError = "Thêm tức tin không thành công" });
                }

            }
            catch
            {
                return RedirectToAction("Error", "Home", new { @MaError = "Thêm tức tin không thành công" });
            }
        }
        public ActionResult Details(int? id)
        {
            //check token còn thời gian k
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
        public ActionResult Edit(int id)
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

        [HttpPost]
        public ActionResult Edit(TinTuc tin, FormCollection collection, HttpPostedFileBase HinhAnh)
        {
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            try
            {
                if (tin.ID != null)
                {
                    TinTuc t = db.TinTucs.SingleOrDefault(x => x.ID == tin.ID);
                    if (HinhAnh != null && HinhAnh.ContentLength > 0)
                    {
                        //Get file name
                        var fileName = Path.GetFileName(HinhAnh.FileName);
                        //Get path
                        var path = Path.Combine(Server.MapPath("~/Content/images"), fileName);

                        //Check exitst
                        if (!System.IO.File.Exists(path))
                        {
                            //Add image into folder
                            HinhAnh.SaveAs(path);



                        }
                        t.HinhAnh = HinhAnh.FileName;



                    }

                    t.NgayDang = DateTime.Now;
                    t.TieuDe = tin.TieuDe;
                    t.MoTaNgan = tin.MoTaNgan;  
                    t.NoiDung = tin.NoiDung;
                    
                    db.Entry(t).State = EntityState.Modified;
                    db.SaveChanges();
                    return RedirectToAction("Success", "Home", new { Success = "Sửa tin tức thành công" });
                }

                else
                {
                    return RedirectToAction("Error", "Home", new { @MaError = "Sửa tức tin không thành công" });
                }
            } catch (Exception ex)
            {
                return RedirectToAction("Error", "Home", new { @MaError = ex.Message });
            }




        }
        public ActionResult Delete(int id)
        {
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            TinTuc nen = db.TinTucs.Find(id);
            if (nen == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            nen.IsDelete = true;
            db.SaveChanges();
            return Json(new { mess = "success" }, JsonRequestBehavior.AllowGet);
        }

        public ActionResult CreateUser(FormCollection collection, User u)
        {
            return View();
        }
        public static string HashPassword(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var saltedPassword = password + salt;
                var passwordBytes = Encoding.UTF8.GetBytes(saltedPassword);
                var hashBytes = sha256.ComputeHash(passwordBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(FormCollection collection, User u)
        {
            string pass = u.Pass;
            string rePass = collection["RePassword"];
            if (!pass.Equals(rePass))
            {
                return RedirectToAction("Error", "Home", new { @MaError = "Mật khẩu không trùng khớp!" });

            }
            if (db.Users.SingleOrDefault(x => x.UserName.Equals(u.UserName)) != null)
            {

                return RedirectToAction("Error", "Home", new { @MaError = "Tên Username đã tồn tại!" });


            }
            
            string hashedPassword = HashPassword(pass, "12345!#aB");
            User user = new User()
            {
                UserName = u.UserName,
                Pass = hashedPassword,
                Role = 1,

            };
            db.Users.Add(user);
            db.SaveChanges();
            return RedirectToAction("Success", "Home", new { Success = "Tạo tài khoản thành công" });
        }

    }
}