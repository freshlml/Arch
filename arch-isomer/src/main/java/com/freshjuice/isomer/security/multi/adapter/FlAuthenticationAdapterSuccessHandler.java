package com.freshjuice.isomer.security.multi.adapter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface FlAuthenticationAdapterSuccessHandler {
    void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException;
}
