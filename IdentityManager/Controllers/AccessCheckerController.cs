using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers {
    [Authorize]
    public class AccessCheckerController : Controller {
        //All requests (including Anon)
        [AllowAnonymous] // overwites parent
        public IActionResult AllAccess() {
            return View();
        }

        [Authorize]
        //All Logged in users
        public IActionResult AuthorizedAccess() {
            return View();
        }

        //Users of User Role
        [Authorize(Roles = "User")]
        public IActionResult UserAccess() {
            return View();
        }

        //Users Or Admins User Role
        [Authorize(Roles = "User,Admin")]
        public IActionResult UserOrAdminAccess() {
            return View();
        }

        //Users AND Admins User Role
        [Authorize(Policy = "UserAndAdmin")]
        public IActionResult UserANDAdminAccess() {
            return View();
        }

        //Users of Admin Role
        [Authorize(Policy = "Admin")]
        public IActionResult AdminAccess() {
            return View();
        }

        //Admin Role / Create Claim
        [Authorize(Policy = "AdminWithCreateClaim")]
        public IActionResult Admin_Create_Access() {
            return View();
        }
        //Admin Role / Create Edit and Delete
        [Authorize(Policy = "AdminWithCreateEditDeleteClaim")]

        public IActionResult Admin_Create_Edit_Delete_Access() {
            return View();
        }

        //Admin Role / Create Edit and Delete, OR Super Admin
        [Authorize(Policy = "AdminWithCreateEditDeleteClaimOrSuperAdminRole")]

        public IActionResult Admin_Create_Edit_Delete_Access_SuperAdmin() {
            return View();
        }

    }
}
