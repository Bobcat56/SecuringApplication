using Common.Models;
using DataAccess.Context;
using DataAccess.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Presentation.Models;

namespace Presentation.Controllers
{
    public class JobsController : Controller
    {
        private JobRepository _jobRepository;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        //Controllers
        public JobsController(JobRepository jobRepository, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _jobRepository = jobRepository;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [Authorize] //Index page full of job listings
        public IActionResult Index()
        {
            var list = _jobRepository.GetAllJobs();
            var jobs = from j in list
                   select new JobViewModel()
                   {
                       Id = j.Id,
                       Title = j.Title,
                       Description = j.Description,
                       Requirments = j.Requirments,
                       PostingDate = j.PostingDate,
                       EmployerId = j.EmployerId,
                   };

            return View(jobs);
        }

        [HttpGet] //Fetch page for data
        [Authorize(Roles = "Admin,Manager,Employer")]
        public IActionResult Create()
        {
            return View();
        }

        [ValidateAntiForgeryToken]
        [HttpPost] //Save Data filled in
        [Authorize(Roles = "Admin,Manager,Employer")]
        public async Task<IActionResult> Create(JobViewModel j) 
        {
            if (ModelState.IsValid)
            {
                try
                {
                    //Getting users id
                    var user = await _userManager.GetUserAsync(User);

                    if (user != null)
                    {
                        Job job = new Job()
                        {
                            Title = j.Title,
                            Description = j.Description,
                            Requirments = j.Requirments,
                            PostingDate = DateOnly.FromDateTime(DateTime.Now),
                            EmployerId = user.Id
                        };

                        _jobRepository.AddJob(job);
                        TempData["SuccessMessage"] = "Job listing added successfully!";
                        return RedirectToAction("Index");
                    }
                }
                catch (Exception)
                {
                    TempData["ErrorMessage"] = "Something went wrong. Please try again.";
                    return View();
                }
            }
            return View();
        }

        //Delete a job listing
        [Authorize(Roles = "Admin,Manager,Employer")]
        public ActionResult Delete(int id)
        {
            var jobToDelete = _jobRepository.GetAllJobs().SingleOrDefault(j => j.Id == id);

            if (jobToDelete != null)
            {
                try
                {
                    _jobRepository.DeleteJob(jobToDelete);
                    TempData["SuccessMessage"] = "Job listing added successfully!";
                    return RedirectToAction("Index");
                }
                catch (Exception)
                {
                    TempData["ErrorMessage"] = "Something went wrong. Please try again.";
                    return RedirectToAction("Index");
                }
            }

            TempData["ErrorMessage"] = "Something went wrong. Please try again.";
            return RedirectToAction("Index");
        }
    }
}
