package com.freshjuice.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.auth.common.vo.JsonResult;
import com.freshjuice.auth.security.AuthAuthenticationFilter;
import com.freshjuice.auth.security.clientdetails.DbClientDetailsService;
import com.freshjuice.auth.security.exception.ClientIdNotNullException;
import com.freshjuice.auth.security.exception.ClientSecretInvalidException;
import com.freshjuice.auth.security.userdetails.AuthUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.io.PrintWriter;


@Configuration
@EnableAuthorizationServer
public class FlOAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AuthUserDetailsService authUserDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private InMemoryAuthorizationCodeServices inMemoryAuthorizationCodeServices;

    @Autowired
    private CompositeTokenGranter customTokenGranter;

    @Autowired
    private DefaultTokenServices defaultTokenServices;

    @Autowired
    private TokenStore redisTokenStore;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //此处设置ClientDetailsService 后于 @Autowired private ClientDetailsService clientDetailsService; 执行
        //而最终 clientDetailsService能够正常 ？？？
        //与AuthorizationServerEndpointsConfigurer.setClientDetailsService的关系
        clients.withClientDetails(new DbClientDetailsService());
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                 .userDetailsService(authUserDetailsService)
                 .tokenStore(redisTokenStore)
                 .authorizationCodeServices(inMemoryAuthorizationCodeServices)
                 .tokenServices(defaultTokenServices)
                 .tokenGranter(customTokenGranter)
                ;
    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        AuthAuthenticationFilter authFilter = new AuthAuthenticationFilter();
        authFilter.setClientDetailsService(clientDetailsService);
        authFilter.setFailureHandler(((request, response, exception) -> {
            response.setContentType("application/json; charset=utf-8");
            PrintWriter out = response.getWriter();
            String msg = exception.getMessage();
            if(exception instanceof ClientIdNotNullException || exception instanceof ClientSecretInvalidException) {
                msg = exception.getMessage();
            }
            out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(msg)));
            out.flush();
            out.close();
        }));
        security.addTokenEndpointAuthenticationFilter(authFilter);
    }



}
