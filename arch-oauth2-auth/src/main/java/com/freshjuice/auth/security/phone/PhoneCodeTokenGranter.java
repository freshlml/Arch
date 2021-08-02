package com.freshjuice.auth.security.phone;

import com.freshjuice.auth.security.exception.PhoneNotFoundException;
import com.freshjuice.auth.security.exception.SmsCodeCheckException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import java.util.LinkedHashMap;
import java.util.Map;

public class PhoneCodeTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "phone_code";

    private final AuthenticationManager authenticationManager;

    public PhoneCodeTokenGranter(AuthenticationManager authenticationManager,
                                 AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = new LinkedHashMap<String, String>(tokenRequest.getRequestParameters());
        String phone = parameters.get("phone");
        String smsCode = parameters.get("sms_code");
        parameters.remove("sms_code");

        Authentication auth = new PhoneCodeAuthenticationToken(phone, smsCode);
        ((AbstractAuthenticationToken) auth).setDetails(parameters);

        try {
            auth = authenticationManager.authenticate(auth);
        } catch (PhoneNotFoundException e) {
            throw new InvalidGrantException(e.getMessage());
        } catch (SmsCodeCheckException e) {
            throw new InvalidGrantException(e.getMessage());
        } catch (Exception e) {
            throw new InvalidGrantException(e.getMessage());
        }
        if (auth == null || !auth.isAuthenticated()) {
            throw new InvalidGrantException("Could not authenticate user: " + phone);
        }

        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, auth);
    }




}
