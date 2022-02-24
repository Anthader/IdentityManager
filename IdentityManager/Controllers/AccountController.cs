using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers {
    [Authorize]
    public class AccountController : Controller {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<IdentityUser> signInManager) {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }


        public IActionResult Index() {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Register(string returnUrl = null) {
            ViewData["ReturnUrl"] = returnUrl;


            if (!await _roleManager.RoleExistsAsync("Admin")) {
                //create roles
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }

            var registerViewModel = new RegisterViewModel();

            List<SelectListItem> roleItems = new List<SelectListItem>();
            var roles = _roleManager.Roles.ToList();
            foreach (var role in roles) {
                roleItems.Add(new SelectListItem() { Value = role.Name, Text = role.Name });
            }

            //List<SelectListItem> listItems = new List<SelectListItem>();
            //listItems.Add(new SelectListItem() { Value = "Admin", Text = "Admin" });
            //listItems.Add(new SelectListItem() { Value = "User", Text = "User" });

            registerViewModel.RoleList = roleItems;

            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null) {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");


            if (ModelState.IsValid) {
                var user = new ApplicationUser {
                    UserName = model.Email,
                    Email = model.Email,
                    Name = model.Name
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded) {
                    if (model.RoleSelected != null && model.RoleSelected.Length > 0  && model.RoleSelected == "Admin") {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    } else {
                        await _userManager.AddToRoleAsync(user, "User");
                    }

                    await _signInManager.SignInAsync(user, false);
                    return LocalRedirect(returnUrl);
                }

                AddErrors(result);
            }

            List<SelectListItem> roleItems = new List<SelectListItem>();
            var roles = _roleManager.Roles.ToList();
            foreach (var role in roles) {
                roleItems.Add(new SelectListItem() { Value = role.Name, Text = role.Name });
            }

            model.RoleList = roleItems;
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff() {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnurl = null) {
            ViewData["ReturnUrl"] = returnurl;
            return View(new LoginViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model, string returnurl) {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");


            if (ModelState.IsValid) {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, true);
                if (result.Succeeded) {
                    return LocalRedirect(returnurl);
                }

                if (result.IsLockedOut) {
                    return View("LockedOut");
                } else {
                    ModelState.AddModelError(string.Empty, "Invalid Login Attempt");
                }
            }

            return View(model);
        }

        private void AddErrors(IdentityResult result) {
            foreach (var error in result.Errors) {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

    }
}
