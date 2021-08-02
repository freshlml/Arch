package com.freshjuice.auth.security.phone;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.freshjuice.auth.common.utils.RedisKeyUtils;
import com.freshjuice.auth.security.entity.User;
import com.freshjuice.auth.security.exception.PhoneNotFoundException;
import com.freshjuice.auth.security.exception.SmsCodeCheckException;
import com.freshjuice.auth.security.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class PhoneCodeAuthenticationProvider implements AuthenticationProvider {

    private Logger log = LoggerFactory.getLogger(PhoneCodeAuthenticationProvider.class);

    private UserService userService;   //TODO，依赖于业务代码

    private UserDetailsService userDetailsService;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper(); //tag

    private RedisTemplate<String, Object> redisTemplate;

    public void setRedisTemplate(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if(!supports(authentication.getClass())) return null;

        PhoneCodeAuthenticationToken token = (PhoneCodeAuthenticationToken) authentication;
        String phone = token.getPhone();
        String smsCode = token.getSmsCode();
        User user = null;

        try {
            user = userService.getOne(new LambdaQueryWrapper<User>().select(User::getId, User::getUserName, User::getPhone).eq(User::getPhone, phone));
        } catch (Exception e) {
            log.error("获取用户信息失败，phone:{}", phone);
            throw new PhoneNotFoundException("phone["+ phone +"]不存在");
        }
        if(user == null) throw new PhoneNotFoundException("phone["+ phone +"]不存在");
        if(smsCode==null || smsCode.length()==0) throw new SmsCodeCheckException("请输入验证码");
        String savedCode = null;
        try {
            savedCode = (String) redisTemplate.opsForValue().get(RedisKeyUtils.getSmsCode(phone));
        } catch (Exception e) {
            log.warn("获取，{}的验证码时发生错误，{}", phone, e);
            throw new SmsCodeCheckException("验证码已失效,phone=["+ phone +"]");
        }
        if(savedCode == null) throw new SmsCodeCheckException("验证码已失效,phone=["+ phone +"]");
        if(!savedCode.equals(smsCode)) throw new SmsCodeCheckException("验证码不匹配");

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUserName());
        PhoneCodeAuthenticationToken resultToken = new PhoneCodeAuthenticationToken(userDetails, null,
                authoritiesMapper.mapAuthorities(userDetails.getAuthorities()));
        resultToken.setDetails(token.getDetails());
        return resultToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (PhoneCodeAuthenticationToken.class.isAssignableFrom(authentication));
    }

}
