package com.freshjuice.auth.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

public class ClientAuthenticationToken extends AbstractAuthenticationToken {

    private String clientId;
    private String clientSecret;

    public ClientAuthenticationToken(String clientId, String clientSecret, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        super.setAuthenticated(true);
    }

    public ClientAuthenticationToken(String clientId, String clientSecret) {
        super(null);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        super.setAuthenticated(false);
    }


    @Override
    public Object getCredentials() {
        return clientSecret;
    }

    @Override
    public Object getPrincipal() {
        return clientId;
    }
}
