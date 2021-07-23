package com.freshjuice.isomer.security;

import com.freshjuice.isomer.security.entity.*;
import com.freshjuice.isomer.security.form.FlDbUserDetailsService;

public class FlSecurityFormSample {

    /**
     * 1、基于浏览器访问的后端系统
     * 2、前后端分离
     * 3、后端系统可单机，可集群部署
     * 4、基于表单的认证，UsernamePasswordAuthenticationFilter
     * 5、可配置的授权
     */

    /**
     * https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzI1NDY0MTkzNQ==&action=getalbum&album_id=1319828555819286528&scene=173&from_msgid=2247488157&from_itemidx=2&count=3&nolastread=1#wechat_redirect
     *
     *
     * 1、配置类: {@link com.freshjuice.isomer.config.FlSecurityFormConfig}
     * 2、基于mysql的资源权限抽象,{@link User},{@link Role},{@link UserRole},{@link ResourcePriority},{@link RoleResource}
     * 3、自定义UserDetailsService,{@link FlDbUserDetailsService},从mysql中查询用户名，密码和permissions
     * 4、所有请求都需要认证: anyRequest().authenticated()
     * 5、配置某些请求需要特定的资源权限,eg: antMatchers("/common/**").hasAuthority("common")
     * 6、session固定会话保护,session失效检查,session同时登录数量控制
     * 7、remember-me
     * 8、支持cors跨域
     * x、集群部署，需要将认证信息保存到redis,默认在Session，浏览器使用cookie, TODO
     *
     * A:未登录前，访问接口(非登录接口)
     * 1、访问非登录接口，UsernamePasswordAuthenticationFilter不执行认证逻辑，而去执行chain
     * 2、RememberMeAuthenticationFilter处理remember-me
     * 3、AnonymousAuthenticationFilter写入一个AnonymousAuthenticationToken，principal=anonymousUser,credentials="",authorities=["ROLE_ANONYMOUS"]
     * 4、FilterSecurityInterceptor执行，根据请求路径计算该路径需要的"资源权限"，如hasAuthority("common"),如果没有则是"authorized"
     *    获取Authentication，上文中的AnonymousAuthenticationToken,判断Auth与"资源权限"比较，此时不匹配
     *    抛出AccessDeniedException
     * 5、异常被ExceptionTranslationFilter捕获，使用AuthenticationEntryPoint响应客户端
     *
     * B:使用UsernamePasswordAuthenticationFilter认证流程
     * /login (其他接口在filter中执行路径匹配，然后chain；只有登录接口才会执行认证逻辑) 注意:前端使用form格式传递userName&password
     * -> UsernamePasswordAuthenticationFilter
     *  认证成功: SessionAuthenticationStrategy处理session, SecurityContextHolder保存SecurityContext到当前线程
     *          RememberMeService处理remember-me逻辑, AuthenticationSuccessHandler响应客户端
     *  认证失败: SecurityContextHolder清空当前线程SecurityContext
     *          RememberMeService处理remember-me逻辑, AuthenticationFailureHandler响应客户端
     *
     * C:LogoutFilter处理退出登录
     * /logout (其他接口在LogoutFilter中执行路径匹配，然后chain；只有退出登录接口才会执行退出逻辑)
     * -> LogoutFilter
     * 退出成功: LogoutSuccessHandler响应客户端
     *
     * D:登录成功后资源权限校验
     * 1、访问无需资源权限的接口
     *    FilterSecurityInterceptor中获取当前Authentication(此时是当前登录用户)的authorities,获取请求路径计算该路径需要的"资源权限"(此时返回"authorized")
     *    校验资源权限通过
     * 2、访问需要资源权限的接口
     *    FilterSecurityInterceptor中获取当前Authentication(此时是当前登录用户)authorities,获取请求路径的"资源权限"(eg: hasAuthority("common"))
     *    校验authorities是否满足请求路径的"资源权限"，满足通过
     *    不满足，抛出AccessDeniedException，异常被ExceptionTranslationFilter捕获，使用accessDeniedHandler处理
     *
     * E:访问不存在的接口
     *   已认证，请求到达spring mvc，handler mapping不存在，抛出异常(需要配置)，异常转发到/error
     *   {
     *     "code": "404",
     *     "success": false,
     *     "message": "path=[/index123];error=[Not Found]"
     *   }
     *   未认证，FilterSecurityInterceptor中判断抛出AccessDeniedException
     *   {
     *     "success": false,
     *     "code": "401",
     *     "message": "未登录"
     *   }
     *
     *
     *
     */

    /**
     *filter chain:
     * org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter
     * org.springframework.security.web.context.SecurityContextPersistenceFilter
     * org.springframework.security.web.header.HeaderWriterFilter
     * org.springframework.web.filter.CorsFilter
     * org.springframework.security.web.csrf.CsrfFilter
     * org.springframework.security.web.authentication.logout.LogoutFilter
     * org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
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
     *
     *
     *
     */




}
