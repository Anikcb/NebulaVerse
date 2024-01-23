using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController : BaseApiController
{
    private readonly DataContext _context;

    public AccountController(DataContext context)
    {
        _context = context;
    }

    [HttpPost("register")] // api/account/register
    public async Task<ActionResult<AppUser>> Register(RegisterDto registerDto)
    {
        if(await UserExist(registerDto.Username))return BadRequest("UserName is Taken!");
        try
        {
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                FullName = registerDto.FullName,
                Email = registerDto.Email,
                PhoneNumber = registerDto.PhoneNumber,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return user;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in Post(): {ex.Message}");
            return StatusCode(500, "Internal Server Error");
        }
        
    }

    [HttpPost("login")]
    public async Task<ActionResult<AppUser>> Login(LoginDto loginDto)
    {
        var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());
        if(user == null)
        {
            return Unauthorized("Invalid Username");
        }

         using var hmac = new HMACSHA512(user.PasswordSalt);
         var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
         for(int i=0; i< computedHash.Length; i++)
         {
            if(computedHash[i] != user.PasswordHash[i])return Unauthorized("Invalid Password");
         }
         return  user;
    }

    private async Task<bool> UserExist(string username)
    {
        return await _context.Users.AnyAsync(x => x.UserName.Equals(username.ToLower()));
    }
}
