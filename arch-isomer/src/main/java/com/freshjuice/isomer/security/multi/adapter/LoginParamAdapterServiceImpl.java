package com.freshjuice.isomer.security.multi.adapter;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.freshjuice.isomer.common.utils.RedisKeyUtils;
import com.freshjuice.isomer.security.entity.User;
import com.freshjuice.isomer.security.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;


@Service
@Slf4j
public class LoginParamAdapterServiceImpl implements LoginParamAdapterService {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private UserService userService;

    @Override
    public User getUserByPhone(String phone) {
        return userService.getOne(new LambdaQueryWrapper<User>().select(User::getId, User::getUserName, User::getPassword, User::getPhone).eq(User::getPhone, phone));
    }

    @Override
    public void checkSmsCode(String phone, String code) {
        if(code==null || code.trim().length()==0) throw new SmsCodeNotEqAdapterException("请输入验证码");
        String savedCode = null;
        try {
            savedCode = (String) redisTemplate.opsForValue().get(RedisKeyUtils.getSmsCode(phone));
        } catch (Exception e) {
            log.warn("获取，{}的验证码时发生错误，{}", phone, e);
            throw new SmsCodeInvalidAdapterException("验证码已失效,phone=["+phone+"]");
        }
        if(savedCode == null) throw new SmsCodeInvalidAdapterException("验证码已失效,phone=["+phone+"]");
        if(!savedCode.equals(code)) throw new SmsCodeNotEqAdapterException("验证码不匹配");
    }

}
