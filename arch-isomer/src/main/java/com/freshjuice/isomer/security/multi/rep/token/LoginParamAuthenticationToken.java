package com.freshjuice.isomer.security.multi.rep.token;

import com.freshjuice.isomer.security.multi.rep.LoginParam;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;


public class LoginParamAuthenticationToken extends AbstractAuthenticationToken {

    private LoginParam loginParam;
    private Object principal;
    private Object credentials;

    public LoginParamAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(true);
    }

    public LoginParamAuthenticationToken(LoginParam loginParam) {
        super(null);
        this.loginParam = loginParam;
    }

    public LoginParamAuthenticationToken(LoginParam loginParam, Object principal, Object credentials) {
        super(null);
        this.loginParam = loginParam;
        this.principal = principal;
        this.credentials = credentials;
    }
    public LoginParamAuthenticationToken(LoginParam loginParam, Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.loginParam = loginParam;
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(true);
    }

    public LoginParam getLoginParam() {
        return loginParam;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
