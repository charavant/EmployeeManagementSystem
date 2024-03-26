using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ServerLibrary.Repositories.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerLibrary.Repositories.Implementations
{
  public class UserAccountRepository : IUserAccount
  {
    public Task<GeneralResponce> CreateAsync(Register user)
    {
      throw new NotImplementedException();
    }

    public Task<LoginResponce> SignInAsync(Login user)
    {
      throw new NotImplementedException();
    }
  }
}
