using AuthenticationService.Dtos;
using AuthenticationService.Helper;
using AuthenticationService.Models;
using AuthenticationService.Repositories;
using AuthenticationService.Repositories.EmployeeRepositories;
using AutoMapper;
using JwtAuthenticationManager;
using JwtAuthenticationManager.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using static Azure.Core.HttpHeader;

namespace AuthenticationService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmployeeAuthenController : ControllerBase
    {

        private readonly JwtTokenHandlerEmp _jwtTokenHandler;
        private readonly IEmployeeRepo _employeeRepo;
        private readonly IMapper _mapper;

        public EmployeeAuthenController(JwtTokenHandlerEmp jwtTokenHandler, IEmployeeRepo employeeRepo, IMapper mapper)
        {
            _jwtTokenHandler = jwtTokenHandler;
            _employeeRepo = employeeRepo;
            _mapper = mapper;
        }

        [HttpPost]
        public ActionResult<AuthenticationEmpResponse?> Authenticate([FromBody] AuthenticationEmpRequest authencationRequest)
        {
            var authenticationResponse = _jwtTokenHandler.GenerateJwtToken(authencationRequest);
            if (authenticationResponse == null) return Unauthorized();
            return authenticationResponse;

        }
        [HttpPost("register")]
        public async Task<ActionResult<EmployeeReadDto>> RegisterEmployee(EmployeeCreateDto employeeCreateDto)
        {
            try
            {
                // Check if email already exists
                if (await _employeeRepo.EmployeeExistsByEmailAsync(employeeCreateDto.Email))
                {
                    return BadRequest("Email already exists.");
                }
               
                // Hash the password
                employeeCreateDto.Password = PasswordHasher.HashPassword(employeeCreateDto.Password);
                employeeCreateDto.CreatedDate = DateOnly.FromDateTime(DateTime.Now);

                var employee = _mapper.Map<Employee>(employeeCreateDto);
                await _employeeRepo.CreateEmployeeAsync(employee);
                var isSaved = await _employeeRepo.SaveChangeAsync();

                if (!isSaved)
                {
                    return StatusCode(500, "Error saving employee to database.");
                }

                var employeeReadDto = _mapper.Map<EmployeeReadDto>(employee);
                return Ok(employeeReadDto);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
    }
}
