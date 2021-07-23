package com.freshjuice.isomer.security.multi.rep.resolver;

import com.freshjuice.isomer.security.multi.rep.LoginParam;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public interface AuthenticationResolver {
    AbstractAuthenticationToken resolve(LoginParam loginParam);
}
