package com.freshjuice.auth.security.logout;

import com.freshjuice.auth.common.utils.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthTokenLogoutHandler implements LogoutHandler {

    private static final String HEADER_TOKEN = "access_token";
    private static final String PARAM_TOKEN = "access_token";

    @Autowired
    private TokenStore tokenStore;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = request.getHeader(HEADER_TOKEN);
        if(StringUtils.isEmpty(token)) {
            token = request.getParameter(PARAM_TOKEN);
        }
        if(!StringUtils.isEmpty(token)) {
            OAuth2AccessToken accessToken = tokenStore.readAccessToken(token);
            if(accessToken != null) {
                if(accessToken.getRefreshToken() != null) {
                    tokenStore.removeRefreshToken(accessToken.getRefreshToken());
                }
                tokenStore.removeAccessToken(accessToken);
            }
        }
    }

}
