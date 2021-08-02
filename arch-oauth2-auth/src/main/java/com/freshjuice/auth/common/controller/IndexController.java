package com.freshjuice.auth.common.controller;

import com.freshjuice.auth.common.bo.redis.RedisTestDto;
import com.freshjuice.auth.common.vo.JsonResult;
import com.freshjuice.auth.config.FlCustomSerializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDateTime;


@RestController
public class IndexController {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private RedisTemplate<String, byte[]> genericRedisTemplate;

    @Autowired
    private FlCustomSerializer flCustomSerializer;


    @GetMapping("/")
    public JsonResult idx() {
        BigInteger bi = new BigInteger("771123123123123123123213123213333333333333333333333333333333333313123123123123123213123123123123123123123121");
        BigDecimal bd = new BigDecimal("8.9999011231312312312323123123123123123123123123123123123123123123123123123234434541353453645364356421432423");
        RedisTestDto pojo = RedisTestDto.builder()
                .id(1234534535354L)
                .bl(false)
                .s(null)
                .name("just pojo哒哒哒")
                .bi(bi)
                .bd(bd)
                .pojoType("SYSTEM")
                .pojoTime(LocalDateTime.now())
                .build();
        redisTemplate.opsForValue().set("AuthPojo", pojo);
        return JsonResult.buildSuccessResult(pojo);
    }
    @GetMapping("/index")
    public JsonResult index() {
        byte[] pojoSources = genericRedisTemplate.opsForValue().get("AuthPojo");
        RedisTestDto pojo = flCustomSerializer.deserialize(pojoSources, RedisTestDto.class);
        return JsonResult.buildSuccessResult(pojo);
    }

}
