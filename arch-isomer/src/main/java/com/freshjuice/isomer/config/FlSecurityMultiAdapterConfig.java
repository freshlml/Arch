package com.freshjuice.isomer.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.isomer.common.constants.CommonConstants;
import com.freshjuice.isomer.common.enums.JsonResultEnum;
import com.freshjuice.isomer.common.vo.AuthenticationSuccessVo;
import com.freshjuice.isomer.common.vo.JsonResult;
import com.freshjuice.isomer.security.form.AuthenticationSuccessVoResolver;
import com.freshjuice.isomer.security.form.CompositeAuthenticationSuccessVoResolver;
import com.freshjuice.isomer.security.form.FlDbUserDetailsService;
import com.freshjuice.isomer.security.multi.adapter.*;
import com.freshjuice.isomer.security.rememberme.RedisTokenRepositoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Arrays;

@Deprecated
//@Configuration
public class FlSecurityMultiAdapterConfig<S extends Session> extends WebSecurityConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;

    @Bean
    public BCryptPasswordEncoder bcryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public FlDbUserDetailsService flDbUserDetailsService() {
        FlDbUserDetailsService result = new FlDbUserDetailsService();
        return result;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }


    /*when using SessionRegistryImpl
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }*/
    @Autowired
    private FindByIndexNameSessionRepository<S> sessionRepository;
    @Bean
    public SpringSessionBackedSessionRegistry<S> springSessionBackedSessionRegistry() {
        return new SpringSessionBackedSessionRegistry<>(this.sessionRepository);
    }
    //spring session中使用Jackson序列化表示很多类(如spring session中的序列化类Authentication实现)不能很好的兼容，所以这里注释掉使用默认的jdk序列化
    /*@Bean
    @Qualifier("springSessionDefaultRedisSerializer")
    public Jackson2JsonRedisSerializer<Object> defaultRedisSerializer() {
        ObjectMapper omToUse = new ObjectMapper();
        omToUse.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        omToUse.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        omToUse.registerModule(JacksonUtils.defaultJavaTimeModule());

        Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(Object.class);
        jackson2JsonRedisSerializer.setObjectMapper(omToUse);

        return jackson2JsonRedisSerializer;
    }*/



    /*@Bean
    public InMemoryTokenRepositoryImpl inMemoryTokenRepositoryImpl() {
        return new InMemoryTokenRepositoryImpl();
    }*/
    @Bean
    public RedisTokenRepositoryImpl flRedisTokenRepository() {
        RedisTokenRepositoryImpl result = new RedisTokenRepositoryImpl();
        return result;
    }

    @Autowired
    private LoginParamAdapterService loginParamService;
    @Bean
    public PhoneLoginParamAdapterResolver phoneLoginParamResolver() {
        PhoneLoginParamAdapterResolver phoneLoginParamResolver = new PhoneLoginParamAdapterResolver(loginParamService);
        return phoneLoginParamResolver;
    }
    @Bean
    public PasswordLoginParamAdapterResolver passwordLoginParamResolver() {
        PasswordLoginParamAdapterResolver passwordLoginParamResolver = new PasswordLoginParamAdapterResolver(loginParamService);
        return passwordLoginParamResolver;
    }
    @Bean
    public CompositeLoginParamAdapterResolver compositeLoginParamResolver() {
        CompositeLoginParamAdapterResolver compositeLoginParamResolver = new CompositeLoginParamAdapterResolver();
        compositeLoginParamResolver.addResolver(phoneLoginParamResolver());
        compositeLoginParamResolver.addResolver(passwordLoginParamResolver());
        return compositeLoginParamResolver;
    }

    //why定义成bean就拦截所有的呢
    //@Bean
    public FlAuthenticationAdapterFilter flAuthenticationPreFilter() {
        FlAuthenticationAdapterFilter flAuthenticationPreFilter = new FlAuthenticationAdapterFilter();
        //跟着loginProcessingUrl("/login")变
        flAuthenticationPreFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login", "POST"));
        //跟着usernameParameter("userName")变
        //跟着passwordParameter("password")变
        //跟着rememberMeParameter("remember-me")变
        flAuthenticationPreFilter.setUsernameParameter("userName");
        flAuthenticationPreFilter.setPasswordParameter("password");
        flAuthenticationPreFilter.setRememberMeParameter("remember-me");
        flAuthenticationPreFilter.setLoginParamResolver(compositeLoginParamResolver());
        flAuthenticationPreFilter.setObjectMapper(objectMapper);
        flAuthenticationPreFilter.setFailureHandler((req, resp, ex) -> {
            resp.setContentType("application/json; charset=utf-8");
            PrintWriter out = resp.getWriter();
            String msg = "登录失败";
            if(ex instanceof AuthenticationException) {
                msg = ex.getMessage();
            }
            out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(msg)));
            out.flush();
            out.close();
        });
        flAuthenticationPreFilter.setSuccessHandler((request, response) -> {
            response.setContentType("application/json; charset=utf-8");
            PrintWriter out = response.getWriter();
            String msg = "请勿重复登录";
            out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult(msg)));
            out.flush();
            out.close();
        });

        return flAuthenticationPreFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(flDbUserDetailsService());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/templates/**", "/favicon.ico", "/error", "/sms/code");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(flAuthenticationPreFilter(), UsernamePasswordAuthenticationFilter.class);

        http.authorizeRequests()
                .antMatchers("/", "/index", "/generateCsrf"/*, "/error"*/).permitAll()
                .antMatchers("/common/**").hasAuthority("common")
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, authException) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(JsonResultEnum.AUTHENTICATION_NEED.getCode(), "未登录")));
                    out.flush();
                    out.close();
                })
                .accessDeniedHandler((req, resp, exp) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    String code = JsonResultEnum.PERMISSION_DENIED.getCode();
                    String msg = "没有权限";
                    if(exp instanceof MissingCsrfTokenException) {
                        code = JsonResultEnum.CSRF_TOKEN_FAIL.getCode();
                        msg = "CSRF token missing";
                    } else if(exp instanceof InvalidCsrfTokenException) {
                        code = JsonResultEnum.CSRF_TOKEN_FAIL.getCode();
                        msg = "CSRF token invalid";
                    }
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(code, msg)));
                    out.flush();
                    out.close();
                })
                .and()
                .headers()
                //.addHeaderWriter(...)
                //.disable()
                //.defaultsDisabled()
                .cacheControl().disable()
                .and()
                .cors()             //cors跨域
                .and()
                .csrf()             //csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //.disable()
                .and()
                .logout()           //logout
                .logoutUrl("/logout")//logout接口地址
                //.logoutSuccessUrl("/")//logout成功后的跳转地址
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult("注销成功")));
                    out.flush();
                    out.close();
                })
                .deleteCookies("s-token")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .formLogin()              //表单认证配置
                //.loginPage("/login.html")  //配置表单认证页面地址
                .usernameParameter("userName")
                .passwordParameter("password")
                .loginProcessingUrl("/login") //配置表单认证接口地址(不是后端的接口地址，而是给前端的地址),数据格式是FormData: userName=..&password=..
                //.defaultSuccessUrl("/")     //表单认证成功后的跳转地址
                .successHandler((req, resp, auth) -> {
                    AuthenticationSuccessVoResolver resolver = new CompositeAuthenticationSuccessVoResolver();
                    AuthenticationSuccessVo result = resolver.createVo(auth, req, resp);
                    //Object principal = auth.getPrincipal();
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult(result)));
                    out.flush();
                    out.close();
                })
                //.failureForwardUrl("/error") //表单认证失败后的跳转地址
                .failureHandler((req, resp, ex) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    String msg = "登录失败";
                    if(ex instanceof UsernameNotFoundException || ex instanceof BadCredentialsException) {
                        msg = "用户名或密码错误";
                    }
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(msg)));
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                .rememberMe()          //remember-me
                .key("rememberMeKey")
                .rememberMeParameter("remember-me")
                .tokenRepository(flRedisTokenRepository())
                .tokenValiditySeconds(CommonConstants.tokenValiditySeconds)
                .and()
                .sessionManagement()    //session-management
                .sessionAuthenticationFailureHandler((req, resp, ex) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(CommonConstants.SYSTEM_ERROR)));
                    out.flush();
                    out.close();
                })
                .maximumSessions(1)
                .sessionRegistry(springSessionBackedSessionRegistry())
                .expiredSessionStrategy(ev -> {
                    HttpServletResponse response = ev.getResponse();
                    response.setContentType("application/json; charset=utf-8");
                    PrintWriter out = response.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(JsonResultEnum.AUTHENTICATION_NEED.getCode(), "登录已过期")));
                    out.flush();
                    out.close();
                });

    }




}
