package com.freshjuice.monomer.shiro;


import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.TimeUnit;


public class ShiroRedisCache<K, V> implements Cache<K, V> {
    private String name;
    private RedisTemplate<K, V> redisTemplate;

    public ShiroRedisCache(String name, RedisTemplate<K, V> redisTemplate) {
        this.name = name;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public V get(K k) throws CacheException {
        return redisTemplate.opsForValue().get(k);
    }

    @Override
    public V put(K k, V v) throws CacheException {
        V vv = get(k);
        redisTemplate.opsForValue().set(k, v, 3600, TimeUnit.SECONDS);
        return vv;
    }

    @Override
    public V remove(K k) throws CacheException {
        V v = redisTemplate.opsForValue().get(k);
        if(v != null) {
            redisTemplate.delete(k);
            return v;
        }
        return null;
    }

    @Override
    public void clear() throws CacheException {
        redisTemplate.delete(keys());
    }

    @Override
    public int size() {
        return keys().size();
    }

    @Override
    public Set<K> keys() {
        return redisTemplate.keys((K)(FlCacheSessionDAO.FL_SHIRO_SESSION_REDIS_PREFIX + ":*"));
    }

    @Override
    public Collection<V> values() {
        return redisTemplate.opsForValue().multiGet(keys());
    }
}
