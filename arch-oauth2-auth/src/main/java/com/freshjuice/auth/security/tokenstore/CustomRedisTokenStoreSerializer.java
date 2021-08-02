package com.freshjuice.auth.security.tokenstore;

import com.freshjuice.auth.config.FlCustomSerializer;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStoreSerializationStrategy;

import java.util.Date;

public class CustomRedisTokenStoreSerializer implements RedisTokenStoreSerializationStrategy {

    private final FlCustomSerializer customSerializer;

    public CustomRedisTokenStoreSerializer(FlCustomSerializer customSerializer) {
        this.customSerializer = customSerializer;
    }

    @Override
    public <T> T deserialize(byte[] bytes, Class<T> clazz) {
        return customSerializer.deserialize(bytes, clazz);
    }

    @Override
    public String deserializeString(byte[] bytes) {
        return customSerializer.deserialize(bytes, String.class);
    }

    @Override
    public byte[] serialize(Object object) {
        return customSerializer.serializeAsBytes(object);
    }

    @Override
    public byte[] serialize(String data) {
        return customSerializer.serializeAsBytes(data);
    }
    
    
    public static void main(String argv[]) {
        
        FlCustomSerializer flCustomSerializer = new FlCustomSerializer();
        
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("refresh_token");
        String refreshTokenSe = flCustomSerializer.serialize(refreshToken);
        DefaultOAuth2RefreshToken refreshTokenDeSe = flCustomSerializer.deserialize(refreshTokenSe, DefaultOAuth2RefreshToken.class);
        System.out.println(refreshTokenSe + " ; " + refreshTokenDeSe);

        /*error
        DefaultExpiringOAuth2RefreshToken refreshToken1 = new DefaultExpiringOAuth2RefreshToken("refresh_token", new Date(System.currentTimeMillis()));
        String refreshTokenSe1 = flCustomSerializer.serialize(refreshToken1);
        DefaultExpiringOAuth2RefreshToken refreshTokenDeSe1 = flCustomSerializer.deserialize(refreshTokenSe1, DefaultExpiringOAuth2RefreshToken.class);
        System.out.println(refreshTokenSe1 + " ; " + refreshTokenDeSe1);*/




    }
    
}
