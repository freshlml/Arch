package com.freshjuice.isomer.security.multi.rep.resolver;

import com.freshjuice.isomer.security.multi.rep.LoginParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAuthenticationResolver implements AuthenticationResolver {

    private Logger log = LoggerFactory.getLogger(AbstractAuthenticationResolver.class);

    public boolean supports(LoginParam loginParam) {
        if(loginParam == null) {
            log.warn("loginParam is null");
            return false;
        }
        return supportsTag().equals(loginParam.getType());
    }

    public abstract String supportsTag();

}
