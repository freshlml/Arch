package com.freshjuice.isomer.security.multi.rep;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.isomer.security.multi.rep.resolver.AuthenticationResolver;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class AuthenticationRepConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<AuthenticationRepConfigurer<H>, H> {

    //private SessionAuthenticationStrategy sessionAuthenticationStrategy;
    //private RememberMeServices rememberMeServices;
    //private AuthenticationManager authenticationManager;

    //private MessageSourceAccessor messages;
    //private boolean continueChainBeforeSuccessfulAuthentication = false;
    //private boolean allowSessionCreation = true;
    //private ApplicationEventPublisher eventPublisher;
    //private boolean permitAll;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    private ObjectMapper objectMapper;
    private String defaultFilterProcessesUrl = "/login";
    private AuthenticationFailureHandler failureHandler;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationSuccessHandler alreadyAuthHandler;
    private AuthenticationResolver authenticationTokenResolver;

    public AuthenticationRepConfigurer<H> alreadyAuthHandler(AuthenticationSuccessHandler alreadyAuthHandler) {
        this.alreadyAuthHandler = alreadyAuthHandler;
        return this;
    }

    public AuthenticationRepConfigurer<H> authenticationTokenResolver(AuthenticationResolver authenticationTokenResolver) {
        this.authenticationTokenResolver = authenticationTokenResolver;
        return this;
    }

    public AuthenticationRepConfigurer<H> objectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        return this;
    }

    public AuthenticationRepConfigurer<H> loginProcessesUrl(String defaultFilterProcessesUrl) {
        this.defaultFilterProcessesUrl = defaultFilterProcessesUrl;
        return this;
    }

    public AuthenticationRepConfigurer<H> successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public AuthenticationRepConfigurer<H> failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    public AuthenticationRepConfigurer<H> authenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return this;
    }

    /*public FlAuthenticationRepConfigurer<H> permitAll() {
        return permitAll(true);
    }

    public FlAuthenticationRepConfigurer<H> permitAll(boolean permitAll) {
        this.permitAll = permitAll;
        return this;
    }*/

    @Override
    public void init(H http) throws Exception {
        //rememberMeServices = http.getSharedObject(RememberMeServices.class);
        //sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
        //authenticationManager = http.getSharedObject(AuthenticationManager.class);
    }

    @Override
    public void configure(H http) throws Exception {
        AuthenticationRepFilter authenticationRepFilter = new AuthenticationRepFilter(defaultFilterProcessesUrl);

        authenticationRepFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        authenticationRepFilter.setSessionAuthenticationStrategy(http.getSharedObject(SessionAuthenticationStrategy.class));
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        authenticationRepFilter.setRememberMeServices(rememberMeServices);

        authenticationRepFilter.setAuthenticationSuccessHandler(successHandler);
        authenticationRepFilter.setAuthenticationFailureHandler(failureHandler);
        authenticationRepFilter.setAlreadyAuthHandler(alreadyAuthHandler);
        authenticationRepFilter.setObjectMapper(objectMapper);
        if(authenticationTokenResolver != null) {
            authenticationRepFilter.setAuthenticationTokenResolver(authenticationTokenResolver);
        }
        if(authenticationDetailsSource != null) {
            authenticationRepFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        }

        if(rememberMeServices != null && rememberMeServices instanceof AbstractRememberMeServices) {
            AbstractRememberMeServices abRemember = (AbstractRememberMeServices) rememberMeServices;
            authenticationRepFilter.setRememberMeParameter(abRemember.getParameter());
        }

        authenticationRepFilter = postProcess(authenticationRepFilter);
        //Filter的顺序实在HttpSecurity的FilterComparator中定义
        http.addFilterBefore(authenticationRepFilter, UsernamePasswordAuthenticationFilter.class);

        RepRequestParamsFilter repRequestParamsFilter = new RepRequestParamsFilter();
        repRequestParamsFilter.setRequestMatcher(new AntPathRequestMatcher(defaultFilterProcessesUrl));
        http.addFilterBefore(repRequestParamsFilter, AuthenticationRepFilter.class);
    }


}
