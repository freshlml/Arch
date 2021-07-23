package com.freshjuice.isomer.security.multi.rep;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.isomer.security.multi.rep.exception.RepAuthenticationPermitException;
import com.freshjuice.isomer.security.multi.rep.resolver.AuthenticationResolver;
import com.freshjuice.isomer.security.multi.rep.resolver.DispatcherAuthenticationResolver;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class AuthenticationRepFilter extends AbstractAuthenticationProcessingFilter {

    private boolean postOnly = true;
    public static final String SPRING_SECURITY_FORM_REMEMBER_ME_KEY = "remember-me";
    private String rememberMeParameter = SPRING_SECURITY_FORM_REMEMBER_ME_KEY;

    private AuthenticationSuccessHandler alreadyAuthHandler;
    private ObjectMapper objectMapper;
    private AuthenticationResolver authenticationTokenResolver = new DispatcherAuthenticationResolver();

    public void setAlreadyAuthHandler(AuthenticationSuccessHandler alreadyAuthHandler) {
        this.alreadyAuthHandler = alreadyAuthHandler;
    }

    public void setAuthenticationTokenResolver(AuthenticationResolver authenticationTokenResolver) {
        this.authenticationTokenResolver = authenticationTokenResolver;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public void setRememberMeParameter(String rememberMeParameter) {
        this.rememberMeParameter = rememberMeParameter;
    }

    public AuthenticationRepFilter() {
        this("/login");
    }

    public AuthenticationRepFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    public AuthenticationRepFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    protected boolean permit(HttpServletRequest request, HttpServletResponse response) {
        boolean jsonMatcher = request.getContentType()!=null && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE);
        return jsonMatcher;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        SecurityContext context = SecurityContextHolder.getContext();
        if(context.getAuthentication()!=null && context.getAuthentication().isAuthenticated()) {
            alreadyAuthHandler.onAuthenticationSuccess(request, response, context.getAuthentication());
            return null;
        }

        if (postOnly && !request.getMethod().equals("POST")) {
            throw new RepAuthenticationPermitException("Authentication method not supported: " + request.getMethod());
        }

        if(!permit(request, response)) {
            throw new RepAuthenticationPermitException("Authentication Content-Type not supported: " + request.getContentType());
        }

        LoginParam loginParam = null;
        try {
            loginParam = objectMapper.readValue(request.getInputStream(), LoginParam.class);
        } catch (Exception e) {
            logger.error("反序列化获取用户登录信息失败, {}", e);
            throw new AuthenticationServiceException("反序列化获取用户登录信息失败, {}", e);
        }

        AbstractAuthenticationToken token = authenticationTokenResolver.resolve(loginParam);
        token.setDetails(authenticationDetailsSource.buildDetails(request));

        //适配remember-me
        //RepRequestParamsWrapper wrappedRequest = new RepRequestParamsWrapper(request);
        //wrappedRequest.setParameter(rememberMeParameter, loginParam.getRememberMe());
        if(RepRequestParamsWrapper.class.isAssignableFrom(request.getClass())) {
            ((RepRequestParamsWrapper) request).setParameter(rememberMeParameter, loginParam.getRememberMe());
        }

        return this.getAuthenticationManager().authenticate(token);
    }
}
