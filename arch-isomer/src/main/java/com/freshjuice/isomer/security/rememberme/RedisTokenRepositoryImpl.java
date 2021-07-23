package com.freshjuice.isomer.security.rememberme;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.isomer.common.constants.CommonConstants;
import com.freshjuice.isomer.common.utils.JacksonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import java.io.Serializable;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class RedisTokenRepositoryImpl implements PersistentTokenRepository {

    public static final String TOKEN_PREFIX_SERIES = "remember-me:token:";
    public static final String TOKEN_PREFIX_USERNAME = "remember-me:username:";

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    public void setRedisTemplate(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void createNewToken(PersistentRememberMeToken token) {
        String currentUserExistsSeries = (String) redisTemplate.opsForValue().get(TOKEN_PREFIX_USERNAME + token.getUsername());
        if(currentUserExistsSeries != null) {
            redisTemplate.delete(TOKEN_PREFIX_SERIES + currentUserExistsSeries);
        }
        PersistentRememberMeTokenWrap tokenWrapper = new PersistentRememberMeTokenWrap(token);
        redisTemplate.opsForValue().set(TOKEN_PREFIX_SERIES + token.getSeries(), tokenWrapper, CommonConstants.tokenValiditySeconds, TimeUnit.SECONDS);
        redisTemplate.opsForValue().set(TOKEN_PREFIX_USERNAME + token.getUsername(), tokenWrapper.getSeries(), CommonConstants.tokenValiditySeconds, TimeUnit.SECONDS);
    }

    @Override
    public void updateToken(String series, String tokenValue, Date lastUsed) {
        PersistentRememberMeTokenWrap existsToken = (PersistentRememberMeTokenWrap) redisTemplate.opsForValue().get(TOKEN_PREFIX_SERIES + series);
        if(existsToken != null) {
            PersistentRememberMeTokenWrap newToken = new PersistentRememberMeTokenWrap(existsToken.getUsername(), series, tokenValue, lastUsed);
            redisTemplate.opsForValue().set(TOKEN_PREFIX_SERIES + series, newToken, CommonConstants.tokenValiditySeconds, TimeUnit.SECONDS);
        }
    }

    @Override
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        PersistentRememberMeTokenWrap result = (PersistentRememberMeTokenWrap) redisTemplate.opsForValue().get(TOKEN_PREFIX_SERIES + seriesId);
        if(result != null) {
            return new PersistentRememberMeToken(result.getUsername(), result.getSeries(), result.getTokenValue(), result.getDate());
        }
        return null;
    }

    @Override
    public void removeUserTokens(String username) {
        String seriesId = (String) redisTemplate.opsForValue().get(TOKEN_PREFIX_USERNAME + username);
        redisTemplate.delete(TOKEN_PREFIX_USERNAME + username);
        if(seriesId != null) {
            redisTemplate.delete(TOKEN_PREFIX_SERIES + seriesId);
        }
    }


    private static class PersistentRememberMeTokenWrap extends PersistentRememberMeToken implements Serializable {
        public PersistentRememberMeTokenWrap() {
            super(null, null, null, null);
        }
        public PersistentRememberMeTokenWrap(PersistentRememberMeToken token) {
            this(token.getUsername(), token.getSeries(), token.getTokenValue(), token.getDate());
        }
        public PersistentRememberMeTokenWrap(String username, String series, String tokenValue, Date date) {
            super(username, series, tokenValue, date);
        }
    }

    public static void main(String argv[]) throws Exception {
        ObjectMapper omToUse = new ObjectMapper();
        omToUse.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        omToUse.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        omToUse.registerModule(JacksonUtils.defaultJavaTimeModule());

        PersistentRememberMeTokenWrap token = new PersistentRememberMeTokenWrap("1", "1", "1", new Date());

        String str = omToUse.writeValueAsString(token);
        System.out.println(str);

        Object t = omToUse.readValue(str, Object.class);
        System.out.println(t);

    }

}
