package com.freshjuice.isomer.security.multi.rep;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RepRequestParamsFilter extends GenericFilter {

    private Logger log = LoggerFactory.getLogger(RepRequestParamsFilter.class);
    static final String FILTER_APPLIED = "__cus_spring_security_rrpf_applied";
    private RequestMatcher requestMatcher;

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return requestMatcher.matches(request);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }
        if (request.getAttribute(FILTER_APPLIED) != null) {
            chain.doFilter(request, response);
            return;
        }
        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

        RepRequestParamsWrapper wrappedRequest = new RepRequestParamsWrapper(request);
        chain.doFilter(wrappedRequest, response);
    }


}
