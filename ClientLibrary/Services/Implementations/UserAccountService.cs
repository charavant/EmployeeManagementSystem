using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ClientLibrary.Helpers;
using ClientLibrary.Services.Contracts;
using System.Net.Http.Json;

namespace ClientLibrary.Services.Implementations
{
  public class UserAccountService(GetHttpClient getHttpClient) : IUserAccountService
  {
    public const string AuthUrl = "api/authentication";
    public async Task<GeneralResponce> CreateAsync(Register user)
    {
      var httpClient = getHttpClient.GetPublicHttpClient();
      var result = await httpClient.PostAsJsonAsync($"{AuthUrl}/register", user);
      if(!result.IsSuccessStatusCode) return new GeneralResponce(false, "Error occured");

      return await result.Content.ReadFromJsonAsync<GeneralResponce>()!;
    }
    public async Task<LoginResponce> SignInAsync(Login user)
    {
      var httpClient = getHttpClient.GetPublicHttpClient();
      var result = await httpClient.PostAsJsonAsync($"{AuthUrl}/login", user);
      if(!result.IsSuccessStatusCode) return new LoginResponce(false, "Error occured");

      return await result.Content.ReadFromJsonAsync<LoginResponce>()!;
    }

    public Task<LoginResponce> RefreshTokenAsync(RefreshToken token)
    {
      throw new NotImplementedException();
    }
    
    public async Task<WeatherForecast[]> GetWeatherForecast()
    {
      var httpClient = getHttpClient.GetPrivateHttpClient();
      var result = await httpClient.Result.GetFromJsonAsync<WeatherForecast[]>("api/weatherforecast");
      return result!;
    }
  }
}
