package com.freshjuice.poner.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.poner.common.enums.JsonResultEnum;
import com.freshjuice.poner.common.vo.JsonResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.PrintWriter;
import java.util.Arrays;

//@Configuration
public class FlOAuth2LoginConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/templates/**", "/favicon.ico", "/error");
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

    /**
     * InMemoryClientRegistrationRepository，并注册为bean
     * ClientRegistration(数据静态)全部存在多个节点上
     * @return
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.githubClientRegistration());
    }
    private ClientRegistration githubClientRegistration() {
        return ClientRegistration.withRegistrationId("github")
                .clientId("780aa2790f5b52bc3a56")
                .clientSecret("75acf6bd2cb1039666670dff58b95f154f168635")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("read:user")
                .authorizationUri("https://github.com/login/oauth/authorize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .userNameAttributeName("id")
                .clientName("GitHub")
                .build();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/common/**").permitAll()
                .antMatchers("/oauth2/**").hasAuthority("oauth2")
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
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(code, msg)));
                    out.flush();
                    out.close();
                })
                //.and()
                //.securityContext() //TODO,默认SecurityContextRepository基于HttpSession,需要重写
                //.securityContextRepository(new NullSecurityContextRepository())
                //.disable()
                .and()
                .cors()
                .and()
                .csrf().disable()    //不依赖于session,cookie，禁用此csrf实现
                .logout()
                .logoutUrl("/logout")
                .clearAuthentication(true)
                .invalidateHttpSession(false)   //不依赖于session
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult("注销成功")));
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                .requestCache().disable()  //禁用requestCache
                .sessionManagement()    //禁用session-management
                //.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .disable()
                .oauth2Login()
                .failureHandler((req, resp, ex) -> {
                    resp.setContentType("application/json; charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    String msg = "登录失败";
                    if(ex instanceof OAuth2AuthenticationException) {
                        msg = ex.getMessage();
                    }
                    out.write(objectMapper.writeValueAsString(JsonResult.buildFailedResult(msg)));
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

        ;

    }

}
