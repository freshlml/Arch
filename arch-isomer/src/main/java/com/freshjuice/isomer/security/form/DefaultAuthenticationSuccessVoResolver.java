package com.freshjuice.isomer.security.form;

import com.freshjuice.isomer.common.utils.CsrfUtils;
import com.freshjuice.isomer.common.vo.AuthenticationSuccessVo;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DefaultAuthenticationSuccessVoResolver implements AuthenticationSuccessVoResolver {

    @Override
    public boolean supports(Class<?> type) {
        return true;
    }

    @Override
    public AuthenticationSuccessVo createVo(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        return AuthenticationSuccessVo.builder().principal(null).credentials(null).permissions(null).loginToken(null).csrfToken(CsrfUtils.readCsrfToken(request, response)).build();
    }
}
