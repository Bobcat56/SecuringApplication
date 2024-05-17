using Common.Models;
using DataAccess.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Presentation.Models;

namespace Presentation.Controllers
{
    
    public class CvController : Controller
    {
        private readonly CvRepository _cvRepository;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IWebHostEnvironment _webHostEnvironment;

        //Controller
        public CvController(CvRepository cvRepository ,UserManager<IdentityUser> userManager, IWebHostEnvironment webHostEnvironment)
        {
            _cvRepository = cvRepository;
            _userManager = userManager;
            _webHostEnvironment = webHostEnvironment;
        }

        [HttpGet] //Fetch page for users submitted cvs
        [Authorize]
        public async Task<IActionResult> UserCvs()
        {
            var user = await _userManager.GetUserAsync(User);

            if (user == null)
            {
                TempData["ErrorMessage"] = "An error occurd while fetching cvs";
                return RedirectToAction("Index", "Home");
            }

            var cvs = _cvRepository.GetCvsByUserId(user.Id);
            var cvViewModels = new List<CvViewModel>();

            try
            {
                foreach (var cv in cvs)
                {
                    var userEmail = await _userManager.FindByIdAsync(cv.UserId);
                    var employerEmail = await _userManager.FindByIdAsync(cv.EmployerId);

                    var cvViewModel = new CvViewModel
                    {
                        Id = cv.Id,
                        FileName = cv.FileName.Substring(37),
                        UserEmail = userEmail.Email,
                        EmployerEmail = employerEmail.Email
                    };

                    cvViewModels.Add(cvViewModel);
                }
                return View(cvViewModels);
            }
            catch (Exception)
            {
                TempData["ErrorMessage"] = "An error occurd while fetching cvs";
                return RedirectToAction("Index", "Home");
            }
        }

        [HttpGet] //Fetch page for users submitted cvs for a pecific job posting
        [Authorize(Roles = "Admin,Manager,Employer")]
        public async Task<IActionResult> EmployerCvs()
        {
            var user = await _userManager.GetUserAsync(User);

            if (user == null)
            {
                TempData["ErrorMessage"] = "An error occurd.";
                return RedirectToAction("Index", "Home");
            }

            var cvs = _cvRepository.GetCvsByEmployerId(user.Id);
            var cvViewModels = new List<CvViewModel>();
            
            try
            {
                foreach (var cv in cvs)
                {
                    var userEmail = await _userManager.FindByIdAsync(cv.UserId);
                    var employerEmail = await _userManager.FindByIdAsync(cv.EmployerId);

                    var cvViewModel = new CvViewModel
                    {
                        Id = cv.Id,
                        FileName = cv.FileName.Substring(37),
                        UserEmail = userEmail.Email,
                        EmployerEmail = employerEmail.Email
                    };

                    cvViewModels.Add(cvViewModel);
                }
                return View(cvViewModels);
            }
            catch (Exception )
            {
                TempData["ErrorMessage"] = "An error occurd while fetching cvs";
                return RedirectToAction("Index", "Home");
            }
        }

        [ValidateAntiForgeryToken]
        [HttpPost] //Allow a logged in user to submit cv
        [Authorize]
        public async Task<IActionResult> Upload(IFormFile cvFile, string employerId)
        {
            
            if (!ModelState.IsValid)
            {
                TempData["ErrorMessage"] = "Only PDF and DOCX files are allowed.";
                return RedirectToAction("Index", "Jobs");
            }

            if (!IsValidFileType(cvFile))
            {
                TempData["ErrorMessage"] = "Only PDF and DOCX files are allowed.";
                return RedirectToAction("Index", "Jobs");
            }

            if (cvFile == null || cvFile.Length <= 0)
            {
                TempData["ErrorMessage"] = "Please select a file to upload.";
                return RedirectToAction("Index", "Jobs");
            }

            if (cvFile.Length > 10 * 1024 * 1024)
            {
                TempData["ErrorMessage"] = "File size cannot be greater than 10MB.";
                return RedirectToAction("Index", "Jobs");
            }

            //Get users ID and the save location
            var user = await _userManager.GetUserAsync(User);

            if (user == null)
            {
                TempData["ErrorMessage"] = "An error has occurd";
                return RedirectToAction("Index", "Home");
            }

            var uploadsFolder = Path.Combine(_webHostEnvironment.ContentRootPath, "Data");

            //On the off chance the directory doesnt exist
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            string uniqueFileName = Guid.NewGuid().ToString() + "_" + cvFile.FileName;
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);

            try
            {
                CV cv = new CV()
                {
                    FileName = uniqueFileName,
                    UserId = user.Id,
                    EmployerId = employerId
                };

                //Save cv
                _cvRepository.AddCv(cv);

                //Save file
                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await cvFile.CopyToAsync(fileStream);
                }

                TempData["SuccessMessage"] = "CV uploaded successfully!";
                return RedirectToAction("Index", "Jobs");
            }
            catch (Exception)
            {
                TempData["ErrorMessage"] = "An error occurd while uploading the file";
                return RedirectToAction("Index", "Jobs");
            }
        }

        private bool IsValidFileType(IFormFile cvFile)
        {
            byte[] buffer = new byte[8];
            using (var stream = cvFile.OpenReadStream())
            {
                stream.Read(buffer, 0, buffer.Length);
            }

            int[] whiteListPdf = new int[] { 37, 80, 68, 70 };
            int[] whiteListDocx = new int[] { 80, 75, 3, 4, 20, 0, 6, 0 };

            //Start off by checking if its a PDF
            if (buffer.Length >= 4)
            {
                bool isPdf = true;
                bool isDocx = true;

                //Go through the list of bytes to check if they match up
                for (int i = 0; i < 4; i++)
                {
                    if (buffer[i] != whiteListPdf[i])
                    {
                        isPdf = false;
                    }
                    if (buffer[i] != whiteListDocx[i])
                    {
                        isDocx = false;
                    }
                }

                if (buffer.Length >= 8 && isDocx) 
                {
                    for (int i = 4; i < 8; i++)
                    {
                        if (buffer[i] != whiteListDocx[i])
                        {
                            isDocx = false;
                            break;
                        }
                    }
                }
                return isPdf || isDocx;
            }
            return false;
        }// Close File type Validation

        [Authorize(Roles = "Admin,Manager,Employer")]
        public IActionResult Download(int cvId)
        {
            var cv = _cvRepository.GetAllCv().SingleOrDefault(x => x.Id == cvId);

            if (cv == null)
            {
                TempData["ErrorMessage"] = "An error occurd while downloading file";
                return RedirectToAction("Index", "Home");
            }

            var uploadsFolder = Path.Combine(_webHostEnvironment.ContentRootPath, "Data");
            var pathToCv = uploadsFolder + "\\" + cv.FileName;

            if (!System.IO.File.Exists(pathToCv))
            {
                TempData["ErrorMessage"] = "File does not exist.";
                return RedirectToAction("Index", "Home");
            }

            byte[] fileAsBytes = System.IO.File.ReadAllBytes(pathToCv);
            string fileName = cv.FileName.Substring(37);

            return File(fileAsBytes, "application/octet-stream", fileName);
        }

    }
}
