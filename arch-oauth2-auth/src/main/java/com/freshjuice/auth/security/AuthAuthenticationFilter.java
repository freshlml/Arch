package com.freshjuice.auth.security;

import com.freshjuice.auth.security.exception.ClientIdNotNullException;
import com.freshjuice.auth.security.exception.ClientSecretInvalidException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthAuthenticationFilter extends OncePerRequestFilter {

    //private static final String GRANT_TYPE = OAuth2Utils.GRANT_TYPE;
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    //private static final String RESPONSE_TYPE = OAuth2Utils.RESPONSE_TYPE;

    private static final String TOKEN_ENDPOINT = "/oauth/token";   //TODO，此请求路径可能会改变，因为FrameworkEndpointHandlerMapping
    private static final String TOKEN_KEY = "/oauth/token_key";
    private static final String CHECK_TOKEN = "/oauth/check_token";
    private RequestMatcher tokenRequestMatcher = new AntPathRequestMatcher(TOKEN_ENDPOINT);
    private RequestMatcher tokenKeyRequestMatcher = new AntPathRequestMatcher(TOKEN_KEY);
    private RequestMatcher checkTokenRequestMatcher = new AntPathRequestMatcher(CHECK_TOKEN);

    private AuthenticationFailureHandler failureHandler = ((request, response, exception) -> {
        throw exception;
    });
    private ClientDetailsService clientDetailsService;

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
    }



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(tokenRequestMatcher.matches(request)) {
            String clientId = request.getParameter(CLIENT_ID);
            String clientSecret = request.getParameter(CLIENT_SECRET);
            if(clientId == null || clientSecret == null) {
                failureHandler.onAuthenticationFailure(request, response, new ClientIdNotNullException("client_id或者client_secret不能为空"));
                return ;
            }

            ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
            if(!clientSecret.equals(client.getClientSecret())) {
                failureHandler.onAuthenticationFailure(request, response, new ClientSecretInvalidException("无效的client_secret"));
                return ;
            }

            ClientAuthenticationToken authentication = new ClientAuthenticationToken(clientId, clientSecret, null);
            //OAuth2Authentication auth = new OAuth2Authentication(null, authentication);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else if(tokenKeyRequestMatcher.matches(request) || checkTokenRequestMatcher.matches(request)) {
            //a null Authentication
            ClientAuthenticationToken authentication = new ClientAuthenticationToken(null, null, null);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

}
