package com.freshjuice.auth.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.auth.common.utils.JacksonUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Bean
    public RedisSerializer<String> stringKeySerializer() {
        return new StringRedisSerializer();
    }

    @Bean
    public RedisSerializer<Object> jacksonValueRedisSerializer(/*, ObjectMapper om*/) {
        //ObjectMapper omToUse = om.copy();
        ObjectMapper omToUse = new ObjectMapper();
        omToUse.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        //omToUse.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        omToUse.activateDefaultTyping(omToUse.getPolymorphicTypeValidator(), ObjectMapper.DefaultTyping.NON_FINAL);
        omToUse.registerModule(JacksonUtils.defaultJavaTimeModule());

        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(Object.class);
        jackson2JsonRedisSerializer.setObjectMapper(omToUse);

        return jackson2JsonRedisSerializer;
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory,
                                                       RedisSerializer<String> stringKeySerializer,
                                                       RedisSerializer<Object> jacksonValueRedisSerializer) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        redisTemplate.setKeySerializer(stringKeySerializer);// key序列化
        redisTemplate.setValueSerializer(jacksonValueRedisSerializer);// value序列化
        redisTemplate.setHashKeySerializer(stringKeySerializer);// Hash key序列化
        redisTemplate.setHashValueSerializer(jacksonValueRedisSerializer);// Hash value序列化
        redisTemplate.afterPropertiesSet();

        return redisTemplate;
    }


    @Bean
    @Qualifier("customRedisTemplate")//the same as StringRedisTemplate
    public RedisTemplate<String, String> customRedisTemplate(RedisConnectionFactory redisConnectionFactory,
                                                             RedisSerializer<String> stringKeySerializer) {
        RedisTemplate<String, String> stringRedisTemplate = new RedisTemplate<>();
        stringRedisTemplate.setConnectionFactory(redisConnectionFactory);

        stringRedisTemplate.setKeySerializer(stringKeySerializer);// key序列化
        stringRedisTemplate.setValueSerializer(stringKeySerializer);// value序列化
        stringRedisTemplate.setHashKeySerializer(stringKeySerializer);// Hash key序列化
        stringRedisTemplate.setHashValueSerializer(stringKeySerializer);// Hash value序列化

        stringRedisTemplate.afterPropertiesSet();
        return stringRedisTemplate;
    }


    @Bean
    public RedisTemplate<String, byte[]> genericRedisTemplate(RedisConnectionFactory redisConnectionFactory,
                                                              RedisSerializer<String> stringKeySerializer) {
        RedisTemplate<String, byte[]> genericRedisTemplate = new RedisTemplate<>();
        genericRedisTemplate.setConnectionFactory(redisConnectionFactory);

        genericRedisTemplate.setEnableDefaultSerializer(false);
        genericRedisTemplate.setKeySerializer(stringKeySerializer);// key序列化
        genericRedisTemplate.setValueSerializer(null);// value序列化，设置为null
        genericRedisTemplate.setHashKeySerializer(stringKeySerializer);// Hash key序列化
        genericRedisTemplate.setHashValueSerializer(null);// Hash value序列化，设置为null

        return genericRedisTemplate;
    }


}
