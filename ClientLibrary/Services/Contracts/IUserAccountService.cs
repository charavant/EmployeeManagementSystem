using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ClientLibrary.Services.Contracts
{
  public interface IUserAccountService
  {
    Task<GeneralResponce> CreateAsync(Register user);
    Task<LoginResponce> SignInAsync(Login user);
    Task<LoginResponce> RefreshTokenAsync(RefreshToken token);
    Task<WeatherForecast[]> GetWeatherForecast();
  }
}
