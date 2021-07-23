package com.freshjuice.isomer.security.form;

import com.freshjuice.isomer.common.vo.AuthenticationSuccessVo;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface AuthenticationSuccessVoResolver {
    boolean supports(Class<?> type);
    AuthenticationSuccessVo createVo(Authentication authentication, HttpServletRequest request, HttpServletResponse response);
}
