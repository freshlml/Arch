package com.freshjuice.isomer.security.multi.rep.token;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.freshjuice.isomer.common.utils.RedisKeyUtils;
import com.freshjuice.isomer.security.entity.User;
import com.freshjuice.isomer.security.multi.rep.LoginParam;
import com.freshjuice.isomer.security.multi.rep.exception.PhoneNotFoundException;
import com.freshjuice.isomer.security.multi.rep.exception.SmsCodeCheckException;
import com.freshjuice.isomer.security.multi.rep.exception.UnSupportedLoginTypeException;
import com.freshjuice.isomer.security.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class LoginParamAuthenticationProvider implements AuthenticationProvider {

    private Logger log = LoggerFactory.getLogger(LoginParamAuthenticationProvider.class);

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private UserService userService;

    @Autowired
    private UserDetailsService userDetailsService;
    //TODO,
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(!supports(authentication.getClass())) return null;

        LoginParamAuthenticationToken token = (LoginParamAuthenticationToken) authentication;
        LoginParam loginParam = token.getLoginParam();
        User user = null;
        switch (loginParam.getType()) {
            case "PHONE":
                try {
                    user = userService.getOne(new LambdaQueryWrapper<User>().select(User::getId, User::getUserName, User::getPhone).eq(User::getPhone, loginParam.getPhone()));
                } catch (Exception e) {
                    log.error("获取用户信息失败，phone:{}", loginParam.getPhone());
                    throw new PhoneNotFoundException("phone["+loginParam.getPhone()+"]不存在");
                }
                if(user == null) throw new PhoneNotFoundException("phone["+loginParam.getPhone()+"]不存在");
                if(loginParam.getSmsCode()==null || loginParam.getSmsCode().length()==0) throw new SmsCodeCheckException("请输入验证码");
                String savedCode = null;
                try {
                    savedCode = (String) redisTemplate.opsForValue().get(RedisKeyUtils.getSmsCode(loginParam.getPhone()));
                } catch (Exception e) {
                    log.warn("获取，{}的验证码时发生错误，{}", loginParam.getPhone(), e);
                    throw new SmsCodeCheckException("验证码已失效,phone=["+loginParam.getPhone()+"]");
                }
                if(savedCode == null) throw new SmsCodeCheckException("验证码已失效,phone=["+loginParam.getPhone()+"]");
                if(!savedCode.equals(loginParam.getSmsCode())) throw new SmsCodeCheckException("验证码不匹配");
                break;
            default:
                throw new UnSupportedLoginTypeException("未知的登录类型,loginParam.type="+loginParam.getType());
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUserName());
        LoginParamAuthenticationToken resultToken = new LoginParamAuthenticationToken(userDetails, null,
                authoritiesMapper.mapAuthorities(userDetails.getAuthorities()));
        resultToken.setDetails(token.getDetails());
        return resultToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (LoginParamAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
