package com.freshjuice.auth.security;

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class FlSessionCheckFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //主要是check一下 /oauth/authorize中用到的HttpSession的情况
        // /oauth/authorize跳转授权页面，HttpSession，attr域中保存authorizationRequest
        // /oauth/authorize确认授权时，HttpSession中attr被清空，但是HttpSession还在,TODO
        HttpSession session = request.getSession(false);
        System.out.println("FlSessionCheckFilter: " + session);
        if(session != null) {
            System.out.println("FlSessionCheckFilter-attr: " + session.getAttribute("authorizationRequest"));
        }

        filterChain.doFilter(request, response);
    }
}
