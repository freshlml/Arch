package com.freshjuice.isomer.security.form;

import com.freshjuice.isomer.common.utils.CsrfUtils;
import com.freshjuice.isomer.common.vo.AuthenticationSuccessVo;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.stream.Collectors;

public class UsernamePasswordAuthenticationTokenSuccessVoResolver implements AuthenticationSuccessVoResolver{
    @Override
    public boolean supports(Class<?> type) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(type));
    }

    @Override
    public AuthenticationSuccessVo createVo(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        UserDetails principalObj = (UserDetails) authentication.getPrincipal();
        String username = principalObj.getUsername();
        String password = (String) authentication.getCredentials();
        List<String> permissions = authentication.getAuthorities().stream().map(au -> au.getAuthority()).collect(Collectors.toList());
        return AuthenticationSuccessVo.builder().principal(username).credentials(password).permissions(permissions).csrfToken(CsrfUtils.readCsrfToken(request, response)).build();
    }
}
