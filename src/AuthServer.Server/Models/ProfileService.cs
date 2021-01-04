using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthServer.Server.Models
{
    /// <summary>
    /// 
    /// </summary>
    public class ProfileService : IProfileService
    {
        /// <summary>
        /// 用户请求userinfo endpoint时会触发该方法
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subjectId = context.Subject.Claims.FirstOrDefault(c => c.Type == "sub").Value;            
            //根据用户id从数据库取得用户信息，写入Claim
            context.IssuedClaims = new List<Claim> {
                new Claim(JwtClaimTypes.Subject,subjectId),
                new Claim(JwtClaimTypes.PreferredUserName,"UserName"),
                new Claim(JwtClaimTypes.Role, "RoleName"),
                new Claim("avatar", "头像"),
                new Claim("CNName", "用户姓名")
            };
            return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            var subjectId = context.Subject.Claims.FirstOrDefault(c => c.Type == "sub").Value;
            context.IsActive = subjectId == "admin";
            return Task.CompletedTask;
        }
    }
}
