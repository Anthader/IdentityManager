using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers {
    public class RolesController : Controller {
        private readonly ApplicationDbContext _dbContext;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(ApplicationDbContext dbContext, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager) {
            this._dbContext = dbContext;
            this._userManager = userManager;
            this._roleManager = roleManager;
        }
        public IActionResult Index() {
            var roles = _dbContext.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string id) {
            if (string.IsNullOrEmpty(id)) {
                //insert
                return View();
            } else {
                //update
                var role = _dbContext.Roles.FirstOrDefault(r => r.Id == id);
                return View(role);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole role) {


            if (string.IsNullOrEmpty(role.Id)) {
                if (await _roleManager.RoleExistsAsync(role.Name)) {
                    TempData[SD.Error] = "Role Already Exists";
                    return RedirectToAction(nameof(Index));
                }
                await _roleManager.CreateAsync(new IdentityRole() { Name = role.Name });
                TempData[SD.Success] = "Role Created Successfully";


            } else {
                //this should also check to make sure there's no duplicate existing!
                var objFromDb = _dbContext.Roles.FirstOrDefault(r => r.Id == role.Id);
                if (objFromDb == null) {
                    TempData[SD.Error] = "Role Not Found";

                    RedirectToAction(nameof(Index));
                }

                objFromDb.Name = role.Name;
                objFromDb.NormalizedName = role.Name.ToUpper();

                TempData[SD.Success] = "Role Updated Successfully";

                var result = await _roleManager.UpdateAsync(objFromDb);
            }
            return RedirectToAction(nameof(Index));
        }


        [HttpPost]
        public async Task<IActionResult> Delete(string id) {
            var objFromDb = _dbContext.Roles.FirstOrDefault(r => r.Id == id);
            var userAssociatedRoles = _dbContext.UserRoles.Where(r => r.RoleId == id).Count();

            if (objFromDb == null) {
                //role not found
                TempData[SD.Error] = "Role not found!";

                return RedirectToAction(nameof(Index));
            }

            if (userAssociatedRoles > 0) {
                //error (toadd for toast)
                TempData[SD.Error] = "Useres currently assigned to role!";

                return RedirectToAction(nameof(Index));

            }

            var result = await _roleManager.DeleteAsync(objFromDb);
            TempData[SD.Success] = "Role Deleted Successfully";

            return RedirectToAction(nameof(Index));

        }


    }
}
