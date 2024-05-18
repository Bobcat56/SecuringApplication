using Common.Models;
using DataAccess.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Presentation.Models;
using Presentation.Utilities;

namespace Presentation.Controllers
{
    
    public class CvController : Controller
    {
        private readonly CvRepository _cvRepository;
        private readonly EncryptionKeyRepository _keyRepository;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IWebHostEnvironment _webHostEnvironment;

        //Controller
        public CvController(
            CvRepository cvRepository,
            EncryptionKeyRepository keyRepository,
            UserManager<IdentityUser> userManager, 
            IWebHostEnvironment webHostEnvironment)
        {
            _cvRepository = cvRepository;
            _userManager = userManager;
            _webHostEnvironment = webHostEnvironment;
            _keyRepository = keyRepository;
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
                        //Add decryption here to show proper file name
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

            var user = await _userManager.GetUserAsync(User);
            if (user == null)//Get user ID, also doubles as a check in case bypassing authorization
            {
                TempData["ErrorMessage"] = "An error has occurd";
                return RedirectToAction("Index", "Home");
            }
            
            var employerKey = _keyRepository.GetKeyById(employerId);
            if (employerKey.PublicKey == null)//Getting employers public key for hybrid encryption
            {
                TempData["ErrorMessage"] = "Employer's encryption key not found.";
                return RedirectToAction("Index", "Jobs");
            }

            var uploadsFolder = Path.Combine(_webHostEnvironment.ContentRootPath, "Data");

            //On the off chance the directory doesnt exist
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            //Giving the file a unique name and concat the file with the directory
            string uniqueFileName = Guid.NewGuid().ToString() + "_" + cvFile.FileName;
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);

            try
            {
                byte[] fileBytes;
                using (var ms = new MemoryStream())
                {
                    await cvFile.CopyToAsync(ms);
                    fileBytes = ms.ToArray();
                }

                var e = new Encryption();

                // Encrypting File using hybrid encryption
                // HAS TO BE DONE BFORE DIGITAL SIGNATURE?!
                MemoryStream encryptedStream = e.HybridEncrypt(fileBytes, employerKey.PublicKey);

                var userPrivateKey = _keyRepository.GetKeyById(user.Id);
                if (userPrivateKey.PrivateKey == null)//Getting users private key for the signature
                {
                    TempData["ErrorMessage"] = "Employer's encryption key not found.";
                    return RedirectToAction("Index", "Jobs");
                }

                //Creating digital signature
                byte[] signature = e.DigitalSign(fileBytes, userPrivateKey.PrivateKey);

                CV cv = new CV()
                {
                    FileName = uniqueFileName,
                    UserId = user.Id,
                    EmployerId = employerId,
                    DigtalSignature = signature,
                };

                //Save CV
                _cvRepository.AddCv(cv);

                // Save the encrypted file
                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    encryptedStream.Position = 0;
                    await encryptedStream.CopyToAsync(fileStream);
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
        public async Task<IActionResult> Download(int cvId)
        {
            var cv = _cvRepository.GetAllCv().SingleOrDefault(x => x.Id == cvId);
            if (cv == null) //Find the CV the employer wants to download
            {
                TempData["ErrorMessage"] = "An error occurd while downloading file";
                return RedirectToAction("EmployerCvs", "Cv");
            }

            //Concat the file name and the directory
            var uploadsFolder = Path.Combine(_webHostEnvironment.ContentRootPath, "Data");
            var pathToCv = uploadsFolder + "\\" + cv.FileName;

            //Check if the file exists
            if (!System.IO.File.Exists(pathToCv))
            {
                TempData["ErrorMessage"] = "File does not exist.";
                return RedirectToAction("EmployerCvs", "Cv");
            }

            try
            {
                //Save encrypted file bytes
                byte[] encryptedFileBytes = System.IO.File.ReadAllBytes(pathToCv);

                var userKey = _keyRepository.GetKeyById(cv.UserId);
                if (userKey.PublicKey == null) //Collect Submitees' public key for digital signature
                {
                    TempData["ErrorMessage"] = "User's encryption key not found.";
                    return RedirectToAction("EmployerCvs", "Cv");
                }

                var e = new Encryption();
                bool verifySignature = e.DigitalVerification(encryptedFileBytes, cv.DigtalSignature, userKey.PublicKey);
                if (!verifySignature)//Validating Digital Signature
                {
                    TempData["ErrorMessage"] = "File signature could not be verified.";
                    return RedirectToAction("EmployerCvs", "Cv");
                }

                // Retrieve employer's private key for decryption
                var employer = await _userManager.FindByIdAsync(cv.EmployerId);
                var employerKey = _keyRepository.GetKeyById(employer.Id);
                if (employerKey.PrivateKey == null) //Check if emplyer has a Private key
                {
                    TempData["ErrorMessage"] = "Employer's encryption key not found.";
                    return RedirectToAction("EmployerCvs", "Cv");
                }

                // Decrypt the file
                MemoryStream decryptedStream = e.HybridDecrypt(encryptedFileBytes, employerKey.PrivateKey);
                //Remove GUID from the file name
                string fileName = cv.FileName.Substring(37);
                //Download file
                return File(decryptedStream, "application/octet-stream", fileName);
            }
            catch (Exception)
            {
                TempData["ErrorMessage"] = "An error occurred while downloading the file.";
                return RedirectToAction("Index", "Home");
            }
        }

    }
}
