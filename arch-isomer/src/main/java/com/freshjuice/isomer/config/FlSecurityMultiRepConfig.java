package com.freshjuice.isomer.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.isomer.common.constants.CommonConstants;
import com.freshjuice.isomer.common.enums.JsonResultEnum;
import com.freshjuice.isomer.common.vo.JsonResult;
import com.freshjuice.isomer.security.multi.rep.AuthenticationRepConfigurer;
import com.freshjuice.isomer.security.multi.rep.exception.*;
import com.freshjuice.isomer.security.multi.rep.token.LoginParamAuthenticationProvider;
import com.freshjuice.isomer.security.multi.rep.userdetails.RepUserDetailsService;
import com.freshjuice.isomer.security.rememberme.RedisTokenRepositoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Arrays;

@Configuration
public class FlSecurityMultiRepConfig<S extends Session> extends WebSecurityConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;

    @Bean
    public BCryptPasswordEncoder bcryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RepUserDetailsService RepUserDetailsService() {
        RepUserDetailsService result = new RepUserDetailsService();
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
    /*@Bean
    @Qualifier("springSessionRedisTaskExecutor")
    public ThreadPoolTaskExecutor springSessionRedisTaskExecutor() {
        ThreadPoolTaskExecutor springSessionRedisTaskExecutor = new ThreadPoolTaskExecutor();
        springSessionRedisTaskExecutor.setCorePoolSize(8);
        springSessionRedisTaskExecutor.setMaxPoolSize(16);
        springSessionRedisTaskExecutor.setKeepAliveSeconds(10);
        springSessionRedisTaskExecutor.setQueueCapacity(1000);
        springSessionRedisTaskExecutor.setThreadNamePrefix("Spring session redis executor thread");

        return springSessionRedisTaskExecutor;
    }*/
//spring session?????????Jackson????????????????????????(???spring session??????????????????Authentication??????)????????????????????????????????????????????????????????????jdk?????????
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
    public RedisTokenRepositoryImpl redisTokenRepository() {
        RedisTokenRepositoryImpl result = new RedisTokenRepositoryImpl();
        return result;
    }

    @Bean
    public LoginParamAuthenticationProvider loginParamAuthenticationProvider() {
        LoginParamAuthenticationProvider provider = new LoginParamAuthenticationProvider();
        return provider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(RepUserDetailsService());
        auth.authenticationProvider(loginParamAuthenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/templates/**", "/favicon.ico", "/error", "/sms/code");
    }


    //@Bean
    /*public FlAuthenticationRepFilter flAuthenticationRepFilter(AuthenticationManager defaultAuthenticationManager,
                                                               RememberMeServices defaultRememberMeServices,
                                                               SessionAuthenticationStrategy defaultSessionAuthenticationStrategy) {
        FlAuthenticationRepFilter result = new FlAuthenticationRepFilter("/login");

        //ApplicationEventPublisher?
        //AuthenticationDetailsSource?
        //MessageSourceAccessor?

        //RememberMeAuthenticationFilter?????????
        result.setAuthenticationManager(defaultAuthenticationManager);

        //RememberMeAuthenticationFilter??????
        result.setRememberMeServices(defaultRememberMeServices);

        //???SessionManagementFilter??????
        result.setSessionAuthenticationStrategy(defaultSessionAuthenticationStrategy);

        result.setAuthenticationSuccessHandler((req, resp, auth) -> {
            Object principalObj = auth.getPrincipal();
            resp.setContentType("application/json; charset=utf-8");
            PrintWriter out = resp.getWriter();
            out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult(principalObj)));
            out.flush();
            out.close();
        });
        result.setAuthenticationFailureHandler((req, resp, ex) -> {
            resp.setContentType("application/json; charset=utf-8");
            PrintWriter out = resp.getWriter();
            String msg = "????????????";
            if(ex instanceof UsernameNotFoundException || ex instanceof BadCredentialsException) {
                msg = "????????????????????????";
            }
            out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(msg)));
            out.flush();
            out.close();
        });

        return result;
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //see ?????????FlAuthenticationRepConfigurer
        /*http.addFilterAt(flAuthenticationRepFilter(http.getSharedObject(AuthenticationManager.class), http.getSharedObject(RememberMeServices.class), http.getSharedObject(SessionAuthenticationStrategy.class)),
                UsernamePasswordAuthenticationFilter.class);*/

        http.authorizeRequests()
                .antMatchers("/", "/index", "/generateCsrf"/*, "/error"*/).permitAll()
                .antMatchers("/common/**").hasAuthority("common")
                .anyRequest().authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, authException) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(JsonResultEnum.AUTHENTICATION_NEED.getCode(), "?????????")));
                    out.flush();
                    out.close();
                })
                .accessDeniedHandler((req, resp, exp) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    String code = JsonResultEnum.PERMISSION_DENIED.getCode();
                    String msg = "????????????";
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
                .cors()             //cors??????
                .and()
                .csrf()             //csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                //.disable()
                .and()
                .logout()           //logout
                .logoutUrl("/logout")//logout????????????
                //.logoutSuccessUrl("/")//logout????????????????????????
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult("????????????")));
                    out.flush();
                    out.close();
                })
                .deleteCookies("s-token")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                /*.formLogin()              //??????????????????
                //.loginPage("/login.html")  //??????????????????????????????
                .usernameParameter("userName")
                .passwordParameter("password")
                .loginProcessingUrl("/login") //??????????????????????????????(??????????????????????????????????????????????????????),???????????????FormData: userName=..&password=..
                //.defaultSuccessUrl("/")     //????????????????????????????????????
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
                //.failureForwardUrl("/error") //????????????????????????????????????
                .failureHandler((req, resp, ex) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    String msg = "????????????";
                    if(ex instanceof UsernameNotFoundException || ex instanceof BadCredentialsException) {
                        msg = "????????????????????????";
                    }
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(msg)));
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                */
                .rememberMe()          //remember-me
                .key("rememberMeKey")
                .tokenRepository(redisTokenRepository())
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
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(JsonResultEnum.AUTHENTICATION_NEED.getCode(), "???????????????")));
                    out.flush();
                    out.close();
                }).and().and()
                .getConfigurer(AuthenticationRepConfigurer.class)  //?????????Configurer: META-INF/spring.factories
                .loginProcessesUrl("/login")
                .objectMapper(objectMapper)
                .alreadyAuthHandler((req, resp, auth) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult("?????????")));
                    out.flush();
                    out.close();
                })
                .successHandler((req, resp, auth) -> {
                    Object principalObj = auth.getPrincipal();
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult(principalObj)));
                    out.flush();
                    out.close();
                })
                .failureHandler((req, resp, ex) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    String msg = "????????????";
                    if(ex instanceof UsernameNotFoundException || ex instanceof BadCredentialsException) {
                        msg = "????????????????????????";
                    } else if(ex instanceof RepAuthenticationPermitException) {
                        msg = ex.getMessage();
                    } else if(ex instanceof LoginParamNotNullException || ex instanceof PhoneNotFoundException
                                    || ex instanceof SmsCodeCheckException || ex instanceof UnSupportedLoginTypeException) {
                        msg = ex.getMessage();
                    }

                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(msg)));
                    out.flush();
                    out.close();
                });


    }


}
