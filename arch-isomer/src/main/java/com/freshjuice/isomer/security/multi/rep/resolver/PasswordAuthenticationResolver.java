package com.freshjuice.isomer.security.multi.rep.resolver;

import com.freshjuice.isomer.security.multi.rep.LoginParam;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class PasswordAuthenticationResolver extends AbstractAuthenticationResolver {

    @Override
    public String supportsTag() {
        return "PASSWORD";
    }

    @Override
    public AbstractAuthenticationToken resolve(LoginParam loginParam) {
        String username = loginParam.getUserName();
        if(username != null) username.trim();
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, loginParam.getPassword());
        return token;
    }

}
