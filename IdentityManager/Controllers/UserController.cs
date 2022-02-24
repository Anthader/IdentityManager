using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityManager.Controllers {
    public class UserController : Controller {
        private readonly ApplicationDbContext _dbContext;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext dbContext, UserManager<IdentityUser> userManager) {
            this._dbContext = dbContext;
            this._userManager = userManager;
        }
        public IActionResult Index() {
            var users = _dbContext.ApplicationUsers.ToList();
            var userRoles = _dbContext.UserRoles.ToList();
            var roles = _dbContext.Roles.ToList();

            foreach (var user in users) {
                var role = userRoles.FirstOrDefault(u => u.UserId == user.Id);
                if (role == null) {
                    user.Role = "None";
                } else {
                    user.Role = roles.FirstOrDefault(u => u.Id == role.RoleId).Name;
                }

            }


            return View(users);
        }

        [HttpGet]
        public IActionResult Edit(string id) {
            var objFromDb = _dbContext.ApplicationUsers.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null) {
                return NotFound();
            }

            var userRoles = _dbContext.UserRoles.ToList();
            var roles = _dbContext.Roles.ToList();
            var role = userRoles.FirstOrDefault(u => u.UserId == objFromDb.Id);

            if (role != null) {
                objFromDb.RoleId = roles.FirstOrDefault(u => u.Id == role.RoleId).Id;
            }

            objFromDb.RoleList = _dbContext.Roles.Select(u => new SelectListItem { Text = u.Name, Value = u.Id });



            return View(objFromDb);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user) {
            if (!ModelState.IsValid) {
                user.RoleList = _dbContext.Roles.Select(u => new SelectListItem { Text = u.Name, Value = u.Id });
                return View(user);
            }
            var objFromDb = _dbContext.ApplicationUsers.FirstOrDefault(u => u.Id == user.Id);
            if (objFromDb == null) {
                return NotFound();
            }

            var userRole = _dbContext.UserRoles.FirstOrDefault(r => r.UserId == user.Id);
            if (userRole != null) {
                var prevRoleNme = _dbContext.Roles.Where(u => u.Id == userRole.RoleId).Select(r => r.Name).FirstOrDefault();
                await _userManager.RemoveFromRoleAsync(objFromDb, prevRoleNme);
            }
            await _userManager.AddToRoleAsync(objFromDb, _dbContext.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
            objFromDb.Name = user.Name;
            _dbContext.SaveChanges();

            TempData[SD.Success] = "User updated successfully!";

            return RedirectToAction(nameof(Index));

        }

        [HttpPost]
        public async Task<IActionResult> LockUnlock(string id) {
            var objFromDb = _dbContext.ApplicationUsers.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null) {
                TempData[SD.Error] = "User Not Found";
                return NotFound();
            }

            if (objFromDb.LockoutEnd != null && objFromDb.LockoutEnd > DateTime.Now) {
                //user is locked
                objFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User account unlocked";
            } else {
                objFromDb.LockoutEnd = DateTime.Now.AddYears(100);
                TempData[SD.Success] = "User account locked";
            }
            _dbContext.SaveChanges();

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public async Task<IActionResult> Delete(string id) {
            var objFromDb = _dbContext.ApplicationUsers.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null) {
                TempData[SD.Error] = "User not found!";
                return RedirectToAction(nameof(Index));
            }

            _dbContext.ApplicationUsers.Remove(objFromDb);
            _dbContext.SaveChanges();
            TempData[SD.Success] = "User Deleted";


            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId) {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) {
                TempData[SD.Error] = "User Not Found";
                return NotFound();
            }
            var existingCliams = await _userManager.GetClaimsAsync(user);

            var model = new UserClaimsViewModel() { UserId = userId };
            foreach (var claim in ClaimStore.claimsList) {
                var userClaim = new UserClaim() {
                    ClaimType = claim.Type,
                    IsSelected = existingCliams.Any(c => c.Type == claim.Type)
                };
                model.Claims.Add(userClaim);
            }
            return View(model);

        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel model) {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) {
                TempData[SD.Error] = "User Not Found";
                return NotFound();
            }

            var existingClaims = await _userManager.GetClaimsAsync(user);            
            if (!(await _userManager.RemoveClaimsAsync(user, existingClaims)).Succeeded) {
                TempData[SD.Error] = "Error Updating Claims";
                return View(model);
            }

            var result = await _userManager.AddClaimsAsync(user, model.Claims.Where(c=>c.IsSelected).Select(c=> new Claim(c.ClaimType, c.IsSelected.ToString())));

            if (result.Succeeded) {
                TempData[SD.Success] = "Claims updated!";
                return RedirectToAction(nameof(Index));
            } else {
                TempData[SD.Error] = "Error Updating Claims";
                return View(model);
            }
        }

    }
}
