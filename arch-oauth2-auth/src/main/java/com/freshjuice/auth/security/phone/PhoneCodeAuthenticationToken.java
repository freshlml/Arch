package com.freshjuice.auth.security.phone;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

public class PhoneCodeAuthenticationToken extends AbstractAuthenticationToken {

    private String phone;
    private String smsCode;

    private Object principal;
    private Object credentials;

    public PhoneCodeAuthenticationToken(String phone, String smsCode) {
        super(null);
        this.phone = phone;
        this.smsCode = smsCode;
        this.setAuthenticated(false);
    }

    public PhoneCodeAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(true);
    }

    public String getPhone() {
        return phone;
    }

    public String getSmsCode() {
        return smsCode;
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
