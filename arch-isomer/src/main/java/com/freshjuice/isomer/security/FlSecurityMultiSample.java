package com.freshjuice.isomer.security;

import com.freshjuice.isomer.config.FlSecurityMultiRepConfig;
import com.freshjuice.isomer.security.multi.rep.AuthenticationRepConfigurer;
import com.freshjuice.isomer.security.multi.rep.AuthenticationRepFilter;

public class FlSecurityMultiSample {

    /**
     *spring security 认证
     * 1、基于浏览器访问的后端系统
     * 2、前后端分离
     * 3、后端系统可集群部署，认证信息保存在session中，session实现共享
     * 4、多种认证方式,spring security web全套组件的使用
     * 5、可配置的授权
     */

 //替换方案
     //定义拦截器处理认证，继承自AbstractAuthenticationProcessingFilter替换UsernamePasswordAuthenticationFilter
     //AbstractAuthenticationProcessingFilter中的组件，链式配置
    /**
     * @see FlSecurityMultiRepConfig
     * @see AuthenticationRepFilter
     * @see AuthenticationRepConfigurer
     */
    /**
     *filter chain:
     * org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter
     * org.springframework.security.web.context.SecurityContextPersistenceFilter
     * org.springframework.security.web.header.HeaderWriterFilter
     * org.springframework.web.filter.CorsFilter
     * org.springframework.security.web.csrf.CsrfFilter
     * org.springframework.security.web.authentication.logout.LogoutFilter
     * com.freshjuice.isomer.security.multi.rep.RepRequestParamsFilter    wrapper request
     * com.freshjuice.isomer.security.multi.rep.AuthenticationRepFilter  替换UsernamePasswordAuthenticationFilter
     * org.springframework.security.web.session.ConcurrentSessionFilter
     * org.springframework.security.web.savedrequest.RequestCacheAwareFilter
     * org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
     * org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
     * org.springframework.security.web.authentication.AnonymousAuthenticationFilter
     * org.springframework.security.web.session.SessionManagementFilter
     * org.springframework.security.web.access.ExceptionTranslationFilter
     * org.springframework.security.web.access.intercept.FilterSecurityInterceptor
     *
     *
     */


 //适配方案
     //适配方案 定义一个UsernamePasswordAuthenticationFilter的前置拦截器
     //如果是JSON参数，则将参数等适配，然后将请求转发到UsernamePasswordAuthenticationFilter
     //如果不是JSON参数,此前置执行直接转发到UsernamePasswordAuthenticationFilter
    /**
     * @see com.freshjuice.isomer.config.FlSecurityMultiAdapterConfig
     * @see com.freshjuice.isomer.security.multi.adapter.FlAuthenticationAdapterFilter
     */



}
