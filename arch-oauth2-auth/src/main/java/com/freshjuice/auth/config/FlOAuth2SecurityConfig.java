package com.freshjuice.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.auth.common.enums.JsonResultEnum;
import com.freshjuice.auth.common.vo.JsonResult;
import com.freshjuice.auth.security.AuthAuthorizeFilter;
import com.freshjuice.auth.security.FlSessionCheckFilter;
import com.freshjuice.auth.security.logout.AuthTokenLogoutHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.io.PrintWriter;
import java.util.Arrays;

@Configuration
public class FlOAuth2SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private DefaultTokenServices defaultTokenServices;

    @Bean
    public AuthTokenLogoutHandler authTokenLogoutHandler() {
        return new AuthTokenLogoutHandler();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/templates/**", "/favicon.ico", "/error", "/sms/code");
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


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        AuthAuthorizeFilter authAuthorizeFilter = new AuthAuthorizeFilter();
        authAuthorizeFilter.setTokenServices(defaultTokenServices);
        http.addFilterBefore(authAuthorizeFilter, BasicAuthenticationFilter.class);
        http.addFilterBefore(new FlSessionCheckFilter(), AnonymousAuthenticationFilter.class);  //for test

        http.authorizeRequests()
                .antMatchers("/oauth/authorize").fullyAuthenticated()
                .anyRequest().permitAll()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, authException) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(JsonResultEnum.AUTHENTICATION_NEED.getCode(), "未登录")));
                    out.flush();
                    out.close();
                })
                /*.accessDeniedHandler((req, resp, exp) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    String code = JsonResultEnum.PERMISSION_DENIED.getCode();
                    String msg = "没有权限";
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(code, msg)));
                    out.flush();
                    out.close();
                })*/
                .and()
                .securityContext()
                .securityContextRepository(new NullSecurityContextRepository())
                .and()
                .cors()
                .and()
                .csrf().disable()
                .logout()
                .logoutUrl("/logout")
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
                .addLogoutHandler(authTokenLogoutHandler())
                .permitAll()
                .and()
                .requestCache().disable()
                .sessionManagement()
                //.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .disable()

        ;

    }

}
