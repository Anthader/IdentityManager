using IdentityManager.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager {
    public class Startup {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use th   is method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));
            services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();

            services.Configure<IdentityOptions>(opt => {
                opt.Password.RequiredLength = 5;
                opt.Password.RequireLowercase = false;
                opt.Password.RequireNonAlphanumeric = false;
                opt.Password.RequireUppercase = false;
                opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(30);
                opt.Lockout.MaxFailedAccessAttempts = 2;

            });
            services.ConfigureApplicationCookie(opt => {
                opt.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Home/AccessDenied");
            });
            services.AddAuthorization(options => {
                options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
                options.AddPolicy("UserAndAdmin", policy => policy.RequireRole("Admin").RequireRole("User"));
                options.AddPolicy("AdminWithCreateClaim", policy => policy.RequireRole("Admin").RequireClaim("Create", "True"));
                options.AddPolicy("AdminWithCreateEditDeleteClaim", policy => policy.RequireRole("Admin")
                                                                            .RequireClaim("Create", "True")
                                                                            .RequireClaim("Edit", "True")
                                                                            .RequireClaim("Delete", "True"));

                options.AddPolicy("AdminWithCreateEditDeleteClaimOrSuperAdminRole",
                    policy => policy.RequireAssertion(context => (
                     (context.User.IsInRole("Admin") && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
                                                     && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
                                                     && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
                    ) || context.User.IsInRole("SuperAdmin")

                    )));

            });

            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            } else {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                //endpoints.MapRazorPages();
            });
        }
    }
}
