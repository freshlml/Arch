package com.freshjuice.isomer.common.controller;

import com.freshjuice.isomer.common.exception.BizException;
import com.freshjuice.isomer.common.utils.RedisKeyUtils;
import com.freshjuice.isomer.common.vo.JsonResult;
import com.freshjuice.isomer.common.vo.SmsCodeVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("sms")
public class SmsController {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @GetMapping("code")
    public JsonResult code(String phone) {
        if(phone == null || phone.length()==0) throw new BizException(() -> "手机号不能为空");
        String verifyCode = String.valueOf(new Random().nextInt(899999) + 100000);
        redisTemplate.opsForValue().set(RedisKeyUtils.getSmsCode(phone), verifyCode, 10, TimeUnit.MINUTES);
        return JsonResult.buildSuccessResult(SmsCodeVo.builder().phone(phone).smsCode(verifyCode).msg("十分钟内有效").build());
    }
}
