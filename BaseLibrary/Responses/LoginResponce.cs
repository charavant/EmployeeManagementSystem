namespace BaseLibrary.Responses
{
  public record LoginResponce(bool Flag, string Message = null!, string Token = null!, string RefreshToken = null!);
}
