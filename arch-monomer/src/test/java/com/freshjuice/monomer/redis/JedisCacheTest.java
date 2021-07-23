package com.freshjuice.monomer.redis;

import com.freshjuice.monomer.BaseJunitTest;
import com.freshjuice.monomer.priority.entity.User;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class JedisCacheTest extends BaseJunitTest {

    //@Autowired
    //private RedisTemplate<Serializable, Serializable> redisTemplate;
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Test
    public void testComm() {
        User user = new User();
        user.setId(1L);
        user.setUserName("吱吱吱吱");
        user.setPhone("15623236821");
        redisTemplate.opsForValue().set("comm:key1", user);

        Object userRet = redisTemplate.opsForValue().get("comm:key1");

        boolean nl = redisTemplate.delete("123");

        Set<String> o = redisTemplate.keys("ShiroSessionRedisPrefix:*");
        Set<String> os = redisTemplate.keys("comm:*");
        //List<Object> oo = redisTemplateComm.opsForValue().multiGet(o);

        redisTemplate.opsForList().rightPush("comm:key2", "hello list 世界");
        redisTemplate.opsForList().rightPush("comm:key2", user);

        List<Object> ops = redisTemplate.opsForList().range("comm:key2", 0, 2);

        redisTemplate.opsForHash().put("comm:key3", "hkey1", "世界 hash");
        Map<Object, Object> hmap = new HashMap<>();
        hmap.put("hkey2", user);
        redisTemplate.opsForHash().putAll("comm:key3", hmap);

        Map<Object, Object> hashRet = redisTemplate.opsForHash().entries("comm:key3");


        System.out.println("11");
    }

    /*@Test
    public void set() {
        boolean ret = redisTemplate.execute(new RedisCallback<Boolean>() {
            @Override
            public Boolean doInRedis(RedisConnection redisConnection) throws DataAccessException {
                return redisConnection.set("key1".getBytes(), "redisTemplate. 世界".getBytes());
            }
        });
        System.out.println(ret);
    }*/

    /*@Test
    public void get() {

        byte[] result = redisTemplate.execute((RedisConnection redisConnection) -> {
            return redisConnection.get("key1".getBytes());
        }, true);

        System.out.println(new String(result));

    }*/



}
