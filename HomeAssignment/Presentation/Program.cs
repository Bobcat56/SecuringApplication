using DataAccess.Context;
using DataAccess.Repositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Presentation
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            builder.Services.AddDbContext<RecruitmentContext>(options =>
                options.UseSqlServer(connectionString));
            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
            {
                //Enabeling a lockout timer to slow down brute forcing of passwords
                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

                //Enforcing a stong password: Length of at least 8, Requires Uppercase & Lowercase, Requires a Digit & Requires a special Char
                options.Password.RequiredLength = 8;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireDigit = true;
                options.Password.RequireNonAlphanumeric = true;

            })
                .AddDefaultUI()
                .AddEntityFrameworkStores<RecruitmentContext>()
                .AddDefaultTokenProviders();

            //Enabling OAuth Login with Microsoft
            builder.Services.AddAuthentication().AddMicrosoftAccount(microsoftOptions =>
            {
                microsoftOptions.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
                microsoftOptions.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
            });

            builder.Services.AddControllersWithViews();

            builder.Services.AddScoped<JobRepository>();
            builder.Services.AddScoped<CvRepository>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");
            app.MapRazorPages();

            // Create roles and admin user (Is there a better place for this? Doesnt seem secure) 
            CreateRolesAndAdminUser(app.Services).Wait();

            app.Run();
        }

        private static async Task CreateRolesAndAdminUser(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
                string[] roleNames = { "Admin", "Employer", "IT Employee", "Manager", "Generic User" };
                IdentityResult roleResult;

                foreach (var roleName in roleNames)
                {
                    var roleExist = await roleManager.RoleExistsAsync(roleName);
                    if (!roleExist)
                    {
                        // Create roles and seed them to the database
                        roleResult = await roleManager.CreateAsync(new IdentityRole(roleName));
                    }
                }

                // Create admin account
                var powerUser = new IdentityUser
                {
                    UserName = "admin@gmail.com",
                    Email = "admin@gmail.com",
                    EmailConfirmed = true
                };

                // Check if the admin user already exists
                var user = await userManager.FindByEmailAsync("admin@gmail.com");

                if (user == null)
                {
                    var createPowerUser = await userManager.CreateAsync(powerUser, "Admin_123");
                    if (createPowerUser.Succeeded)
                    {
                        // Here we assign the admin role to the user
                        await userManager.AddToRoleAsync(powerUser, "Admin");
                    }
                }
            }
        }
    }
}
