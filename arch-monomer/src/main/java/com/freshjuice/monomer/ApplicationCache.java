package com.freshjuice.monomer;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.monomer.common.utils.JacksonUtils;
import org.apache.shiro.session.Session;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.redis.connection.RedisClusterConfiguration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisNode;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import redis.clients.jedis.JedisPoolConfig;

import java.util.ArrayList;
import java.util.List;


@Configuration
@PropertySource(value={"classpath:redis.properties"})
public class ApplicationCache {

    //RedisCacheManager
    /*@Bean
    public CacheManager cacheManager(RedisConnectionFactory jedisClusterConectionFactory) {
        //RedisCacheWriter
        RedisCacheWriter redisCacheWriter = RedisCacheWriter.nonLockingRedisCacheWriter(jedisClusterConectionFactory);

        RedisCacheConfiguration redisCacheConfiguration = RedisCacheConfiguration.defaultCacheConfig();

        CacheManager cacheManager = new RedisCacheManager(redisCacheWriter, redisCacheConfiguration);
        return cacheManager;
    }*/


    @Bean
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(jedisClusterConnectionFactory());

        ObjectMapper omToUse = new ObjectMapper();
        omToUse.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        omToUse.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        omToUse.registerModule(JacksonUtils.defaultJavaTimeModule());

        RedisSerializer<?> stringSerializer = new StringRedisSerializer();
        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(Object.class);
        jackson2JsonRedisSerializer.setObjectMapper(omToUse);

        redisTemplate.setKeySerializer(stringSerializer);// key序列化
        redisTemplate.setValueSerializer(jackson2JsonRedisSerializer);// value序列化
        redisTemplate.setHashKeySerializer(stringSerializer);// Hash key序列化
        redisTemplate.setHashValueSerializer(jackson2JsonRedisSerializer);// Hash value序列化
        redisTemplate.afterPropertiesSet();

        return redisTemplate;
    }

    @Bean
    @Qualifier("customRedisTemplate")//the same as StringRedisTemplate
    public RedisTemplate<String, String> customRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, String> stringRedisTemplate = new RedisTemplate<>();
        stringRedisTemplate.setConnectionFactory(redisConnectionFactory);

        RedisSerializer<?> stringSerializer = new StringRedisSerializer();
        stringRedisTemplate.setKeySerializer(stringSerializer);// key序列化
        stringRedisTemplate.setValueSerializer(stringSerializer);// value序列化
        stringRedisTemplate.setHashKeySerializer(stringSerializer);// Hash key序列化
        stringRedisTemplate.setHashValueSerializer(stringSerializer);// Hash value序列化

        stringRedisTemplate.afterPropertiesSet();
        return stringRedisTemplate;
    }


    @Bean
    public RedisTemplate<String, byte[]> genericRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, byte[]> genericRedisTemplate = new RedisTemplate<>();
        genericRedisTemplate.setConnectionFactory(redisConnectionFactory);

        RedisSerializer<?> stringSerializer = new StringRedisSerializer();

        genericRedisTemplate.setEnableDefaultSerializer(false);
        genericRedisTemplate.setKeySerializer(stringSerializer);// key序列化
        genericRedisTemplate.setValueSerializer(null);// value序列化，设置为null
        genericRedisTemplate.setHashKeySerializer(stringSerializer);// Hash key序列化
        genericRedisTemplate.setHashValueSerializer(null);// Hash value序列化，设置为null

        return genericRedisTemplate;
    }


    @Bean
    public RedisTemplate<String, Session> redisTemplateRedisSession() {
        RedisTemplate<String, Session> redisTemplate = new RedisTemplate<>();
        redisTemplate.setKeySerializer(RedisSerializer.string());
        redisTemplate.setValueSerializer(RedisSerializer.java());
        redisTemplate.setHashKeySerializer(RedisSerializer.string());
        redisTemplate.setHashValueSerializer(RedisSerializer.java());
        redisTemplate.setConnectionFactory(jedisClusterConnectionFactory());
        return redisTemplate;
    }


    //RedisConnectionFactory using JedisClusterConnectionFactory
    @Bean
    public JedisConnectionFactory jedisClusterConnectionFactory() {
        JedisConnectionFactory jedisConnectionFactory =
                new JedisConnectionFactory(redisClusterConfiguration(), jedisPoolConfig());
        return jedisConnectionFactory;
    }

    @Value("${jedis.cluster.node1.host:#{localhost}}")
    private String node1Host;
    @Value("${jedis.cluster.node1.port:#{6379}}")
    private int node1Port;
    @Value("${jedis.cluster.node2.host:#{localhost}}")
    private String node2Host;
    @Value("${jedis.cluster.node2.port:#{6379}}")
    private int node2Port;
    @Value("${jedis.cluster.node3.host:#{localhost}}")
    private String node3Host;
    @Value("${jedis.cluster.node3.port:#{6379}}")
    private int node3Port;
    //RedisClusterConfiguration
    @Bean
    public RedisClusterConfiguration redisClusterConfiguration() {
        RedisClusterConfiguration redisClusterConfiguration = new RedisClusterConfiguration();
        List<RedisNode> nodes = new ArrayList<RedisNode>();
        nodes.add(new RedisNode(node1Host, node1Port));
        nodes.add(new RedisNode(node2Host, node2Port));
        nodes.add(new RedisNode(node3Host, node3Port));
        redisClusterConfiguration.setClusterNodes(nodes);
        return redisClusterConfiguration;
    }

    @Value("${jedis.pool.maxTotal:#{1000}}")
    private int maxTotal;
    @Value("${jedis.pool.minIdle:#{50}}")
    private int minIdle;
    @Value("${jedis.pool.maxIdle:#{100}}")
    private int maxIdle;
    @Value("${jedis.pool.maxWaitMillis:#{10000}}")
    private long maxWaitMillis;
    //JedisPoolConfig
    @Bean
    public JedisPoolConfig jedisPoolConfig() {
        JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
        jedisPoolConfig.setMinIdle(minIdle);
        jedisPoolConfig.setMaxIdle(maxIdle);
        jedisPoolConfig.setMaxTotal(maxTotal);
        jedisPoolConfig.setMaxWaitMillis(maxWaitMillis);
        return jedisPoolConfig;
    }



}
