package com.freshjuice.auth.security;

import com.freshjuice.auth.common.utils.StringUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthAuthorizeFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_ENDPOINT = "/oauth/authorize";
    private static final String HEADER_TOKEN = "access_token";
    private RequestMatcher authorizeRequestMatcher = new AntPathRequestMatcher(AUTHORIZATION_ENDPOINT);

    private ResourceServerTokenServices tokenServices;

    public void setTokenServices(ResourceServerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(authorizeRequestMatcher.matches(request)) {
            String token = request.getHeader(HEADER_TOKEN);
            if(!StringUtils.isEmpty(token)) {
                try {
                    OAuth2Authentication oAuth2Authentication = tokenServices.loadAuthentication(token);
                    SecurityContextHolder.getContext().setAuthentication(oAuth2Authentication.getUserAuthentication());
                } catch (Exception e) {
                    //do nothing
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
