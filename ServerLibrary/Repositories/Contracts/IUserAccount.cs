using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ServerLibrary.Repositories.Contracts
{
  public interface IUserAccount
  {
    Task<GeneralResponce> CreateAsync(Register user);
    Task<LoginResponce> SignInAsync(Login user);
    Task<LoginResponce> RefreshTokenAsync(RefreshToken refreshToken);
  }
}
