package com.freshjuice.auth.config;


import com.freshjuice.auth.security.phone.PhoneCodeAuthenticationProvider;
import com.freshjuice.auth.security.phone.PhoneCodeTokenGranter;
import com.freshjuice.auth.security.service.UserService;
import com.freshjuice.auth.security.tokenstore.CustomRedisTokenStoreSerializer;
import com.freshjuice.auth.security.userdetails.AuthUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@Configuration
public class FlOAuth2AuthorizationComponentConfig {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private ClientDetailsService clientDetailsService;
    /*@Bean
    public DbClientDetailsService dbClientDetailsService() {
        return new DbClientDetailsService();
    }*/

    @Autowired
    private UserService userService;

    @Autowired
    private FlCustomSerializer flCustomSerializer;

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthUserDetailsService authUserDetailsService() {
        return new AuthUserDetailsService();
    }


    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(authUserDetailsService());

        PhoneCodeAuthenticationProvider phoneCodeAuthenticationProvider = new PhoneCodeAuthenticationProvider();
        phoneCodeAuthenticationProvider.setUserService(userService);
        phoneCodeAuthenticationProvider.setUserDetailsService(authUserDetailsService());
        phoneCodeAuthenticationProvider.setRedisTemplate(redisTemplate);

        ProviderManager providerManager = new ProviderManager(daoAuthenticationProvider, phoneCodeAuthenticationProvider);
        return providerManager;
    }

    @Bean
    public InMemoryAuthorizationCodeServices inMemoryAuthorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }

    @Bean
    public CustomRedisTokenStoreSerializer customRedisTokenStoreSerializer() {
        return new CustomRedisTokenStoreSerializer(flCustomSerializer);
    }

    /*@Bean
    public TokenStore inMemoryTokenStore() {
        InMemoryTokenStore inMemoryTokenStore = new InMemoryTokenStore();
        return inMemoryTokenStore;
    }*/

    @Bean
    public TokenStore redisTokenStore() {
        RedisTokenStore tokenStore = new RedisTokenStore(redisConnectionFactory);
        //tokenStore.setSerializationStrategy(customRedisTokenStoreSerializer()); //TODO,using jackson序列化
        tokenStore.setPrefix("oauth2:");

        return tokenStore;
    }

    @Bean
    public DefaultTokenServices defaultTokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(redisTokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setReuseRefreshToken(true);
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        defaultTokenServices.setTokenEnhancer(null);

        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(new UserDetailsByNameServiceWrapper<>(authUserDetailsService()));
        defaultTokenServices.setAuthenticationManager(new ProviderManager(Arrays.asList(provider)));

        return defaultTokenServices;
    }

    @Bean
    public CompositeTokenGranter customTokenGranter() {
        List<TokenGranter> tokenGranters = new ArrayList<>();

        AuthorizationServerTokenServices tokenServices = defaultTokenServices();
        AuthorizationCodeServices authorizationCodeServices = inMemoryAuthorizationCodeServices();
        OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService); //tag

        tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory));
        tokenGranters.add(new RefreshTokenGranter(tokenServices, clientDetailsService, requestFactory));
        tokenGranters.add(new ImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory));
        tokenGranters.add(new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory));

        AuthenticationManager authenticationManager = authenticationManager();
        tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices, clientDetailsService, requestFactory));
        tokenGranters.add(new PhoneCodeTokenGranter(authenticationManager, tokenServices, clientDetailsService, requestFactory));

        CompositeTokenGranter tokenGranter = new CompositeTokenGranter(tokenGranters);
        return tokenGranter;
    }





}
