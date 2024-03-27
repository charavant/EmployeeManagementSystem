using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ServerLibrary.Repositories.Implementations
{
  public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext appDbContext) : IUserAccount
  {
    public async Task<GeneralResponce> CreateAsync(Register user)
    {
      if (user is null) return new GeneralResponce(false, "Model is empty");

      var checkUser = await FindUserByEmail(user.Email);
      if (checkUser != null) return new GeneralResponce(false, "User already exists");

      //Save user
      var applicationUser = await AddToDatabase(new ApplicationUser()
      {
        Fullname = user.Fullname,
        Email = user.Email,
        Password = BCrypt.Net.BCrypt.HashPassword(user.Password),
      });

      // check, create and assign role to Admin
      var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
      if (checkAdminRole == null)
      {
        var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
        await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
        return new GeneralResponce(true, "Account created");
      }
      
      // check, create and assign role to User
      var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
      if (checkUserRole == null)
      {
        var response = await AddToDatabase(new SystemRole() { Name = Constants.User });
        await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
      }
      else
      {
        await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
      }
      return new GeneralResponce(true, "Account created");
    }

    public async Task<LoginResponce> SignInAsync(Login user)
    {
      if (user is null) return new LoginResponce(false,"Model is empty");

      var applicationUser = await FindUserByEmail(user.Email!);
      if (applicationUser == null) return new LoginResponce(false, "User not found");

      // Verify password
      if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
        return new LoginResponce(false, "Email/Password not valid");

      var getUserRole = await FindUserRole(applicationUser.Id);
      if (getUserRole is null) return new LoginResponce(false, "User role not found");

      var getRoleName = await FindRoleName(getUserRole.RoleId);
      if (getRoleName is null) return new LoginResponce(false, "User Role not found");

      string jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
      string refreshToken = GenerateRefreshToken();

      var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
      if (findUser is not null)
      {
        findUser!.Token = refreshToken;
        await appDbContext.SaveChangesAsync();
      }
      else
      {
        await AddToDatabase(new RefreshTokenInfo() { Token = refreshToken, UserId = applicationUser.Id });
      }
      return new LoginResponce(true, "Login Successfully", jwtToken, refreshToken);
    }


    private string GenerateToken(ApplicationUser user, string role)
    {
      var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
      var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
      var userClaims = new[]
      {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Fullname!),
        new Claim(ClaimTypes.Email, user.Email!),
        new Claim(ClaimTypes.Role, role),
      };
      var token = new JwtSecurityToken(
        issuer : config.Value.Issuer, 
        audience : config.Value.Audience, 
        claims : userClaims, 
        expires : DateTime.Now.AddDays(1), 
        signingCredentials: credentials
        );
      return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<UserRole> FindUserRole(int userId) => await appDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == userId);
    private async Task<SystemRole> FindRoleName(int roleId) => await appDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == roleId);
    private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    
    private async Task<ApplicationUser> FindUserByEmail(string email)
      => await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_=> _.Email!.ToLower()!.Equals(email!.ToLower()));

    private async Task<T> AddToDatabase<T>(T model)
    {
      var result = appDbContext.Add(model!);
      await appDbContext.SaveChangesAsync();
      return (T)result.Entity;
    }

    public async Task<LoginResponce> RefreshTokenAsync(RefreshToken token)
    {
      if (token is null) return new LoginResponce(false, "Model is empty");

      var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token!.Equals(token.Token));
      if (findToken is null) return new LoginResponce(false, "Refresh Token not found");

      // get user details
      var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Id == findToken.UserId);
      if (user is null) return new LoginResponce(false, "Refresh token could not be generated because user not found");

      // get user role
      var userRole = await FindUserRole(user.Id);
      var roleName = await FindRoleName(userRole!.RoleId);
      string jwtToken = GenerateToken(user, roleName!.Name!);
      string refreshToken = GenerateRefreshToken();

      var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token!.Equals(token.Token));
      if (updateRefreshToken is null) return new LoginResponce(false, "Refresh token could not be generated because user has not signed in");

      updateRefreshToken.Token = refreshToken;
      await appDbContext.SaveChangesAsync();
      return new LoginResponce(true, "Token Refreshed successfully", jwtToken, refreshToken);
    }
  }
}
