package com.freshjuice.isomer.security.multi.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class FlAuthenticationAdapterFilter extends GenericFilter {

    private Logger log = LoggerFactory.getLogger(FlAuthenticationAdapterFilter.class);
    static final String FILTER_APPLIED = "__cus_spring_security_fapf_applied";
    private boolean postOnly = true;
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
    public static final String SPRING_SECURITY_FORM_REMEMBER_ME_KEY = "remember-me";

    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
    private String rememberMeParameter = SPRING_SECURITY_FORM_REMEMBER_ME_KEY;
    private String headerTag = "AUTH";
    private String headerTagValue = "JSON";
    private ObjectMapper objectMapper;
    private LoginParamAdapterResolver loginParamResolver = new CompositeLoginParamAdapterResolver();

    private RequestMatcher requiresAuthenticationRequestMatcher = new AntPathRequestMatcher("/login", "POST");
    private FlAuthenticationAdapterFailureHandler failureHandler;
    private FlAuthenticationAdapterSuccessHandler successHandler;

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public void setSuccessHandler(FlAuthenticationAdapterSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    public void setFailureHandler(FlAuthenticationAdapterFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
    }

    public void setLoginParamResolver(LoginParamAdapterResolver loginParamResolver) {
        this.loginParamResolver = loginParamResolver;
    }

    public void setRememberMeParameter(String rememberMeParameter) {
        this.rememberMeParameter = rememberMeParameter;
    }

    public void setUsernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        this.passwordParameter = passwordParameter;
    }

    public void setRequiresAuthenticationRequestMatcher(RequestMatcher requestMatcher) {
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
    }

    //保持和UsernamePasswordAuthenticationFilter和AbstractAuthenticationProcessingFilter相同的check逻辑
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        boolean pathMatcher = requiresAuthenticationRequestMatcher.matches(request);
        boolean postOnlyMatcher = postOnly && request.getMethod().equals("POST");
        //boolean headerMatcher = headerTagValue.equals(request.getHeader(headerTag));
        //boolean jsonMatcher = request.getContentType()!=null && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE);

        return pathMatcher && postOnlyMatcher /*&& (headerMatcher || jsonMatcher)*/;
    }

    protected boolean permit(HttpServletRequest request, HttpServletResponse response) {
        boolean headerMatcher = headerTagValue.equals(request.getHeader(headerTag));
        boolean jsonMatcher = request.getContentType()!=null && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE);

        return (headerMatcher || jsonMatcher);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }

        //TODO 如果已经认证通过，则直接返回
        /*HttpSession existsSession = request.getSession(false);
        if(existsSession != null) {
            successHandler.onAuthenticationSuccess(request, response);
            return;
        }*/

        if(!permit(request, response)) {
            chain.doFilter(request, response);
            return;
        }

        if (request.getAttribute(FILTER_APPLIED) != null) {
            chain.doFilter(request, response);
            return;
        }
        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

        CusParamsRequestWrapper wrappedRequest = new CusParamsRequestWrapper(request);

        LoginParamAdapter loginParam = null;
        try {
            loginParam = objectMapper.readValue(wrappedRequest.getInputStream(), LoginParamAdapter.class);
        } catch(Exception e) {
            log.error("反序列化获取用户登录信息失败, {}", e);
            throw new AuthenticationAdapterException("反序列化获取用户登录信息失败", e);
        }
        LoginParamAdapter loginParamResolved;
        try {
            loginParamResolved = loginParamResolver.resolve(loginParam);
        } catch (AuthenticationException e) {
            failureHandler.onAuthenticationFailure(wrappedRequest, response, e);
            return ;
        }
        //TODO?如果是phone登录，根据phone取出来的password是密文，适配失败
        wrappedRequest.setParameter(usernameParameter, loginParamResolved.getUserName());
        wrappedRequest.setParameter(passwordParameter, loginParamResolved.getPassword());
        wrappedRequest.setParameter(rememberMeParameter, loginParamResolved.getRememberMe());

        chain.doFilter(wrappedRequest, response);

    }

    private final class CusParamsRequestWrapper extends HttpServletRequestWrapper {
        private final Map<String, String[]> cusParams = new HashMap<>();

        public CusParamsRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        public void setParameter(String name, String val) {
            cusParams.put(name, new String[]{val});
        }
        public void setParameters(String name, String[] val) {
            cusParams.put(name, val);
        }

        /**
         * 先从cusParams取，如果存在，则返回(这将意味着可能覆盖super中的)，如果不存在，返回super
         * @param name
         * @return
         */
        @Override
        public String getParameter(String name) {
            String[] val = cusParams.get(name);
            return (val != null && val[0] != null) ? val[0] : super.getParameter(name);
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] val = cusParams.get(name);
            return (val != null && val.length > 0) ? val : super.getParameterValues(name);
        }

        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> mapParent = super.getParameterMap();
            if(mapParent == null) mapParent = new HashMap<>();
            cusParams.forEach(mapParent::put);
            return mapParent;
        }

        @Override
        public Enumeration<String> getParameterNames() {
            Enumeration<String> keyParent = super.getParameterNames();
            Set<String> key = cusParams.keySet();
            if(key == null) key = new HashSet<>();
            while(keyParent.hasMoreElements()) {
                key.add(keyParent.nextElement());
            }
            Vector<String> vector = new Vector<>();
            vector.addAll(key);
            return vector.elements();
            /*Vector<String> vector = new Vector<>();
            Set<String> key = cusParams.keySet();
            if(key != null) key.stream().filter(name -> !vector.contains(name)).map(vector::add);
            Enumeration<String> keyParent = super.getParameterNames();
            while(keyParent.hasMoreElements()) {
                String el = keyParent.nextElement();
                if(!vector.contains(el)) vector.add(el);
            }
            return vector.elements();*/
        }



    }


}
