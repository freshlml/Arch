package com.freshjuice.isomer.common.utils;

import org.springframework.security.web.csrf.CsrfToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class CsrfUtils {

    public static String readCsrfToken(HttpServletRequest request, HttpServletResponse response) {
        String token = null;
        try {
            CsrfToken t = (CsrfToken) request.getAttribute("_csrf");
            token = t.getToken();
        } catch (Exception e) {
            token = null;
        }
        return token;
    }

}
