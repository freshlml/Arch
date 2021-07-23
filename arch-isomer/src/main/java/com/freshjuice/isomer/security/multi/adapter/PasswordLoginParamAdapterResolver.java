package com.freshjuice.isomer.security.multi.adapter;

import org.springframework.security.core.AuthenticationException;

public class PasswordLoginParamAdapterResolver extends AbstractLoginParamAdapterResolver {

    public PasswordLoginParamAdapterResolver(LoginParamAdapterService loginParamService) {
        super(loginParamService);
    }

    @Override
    protected String getSupportsTag() {
        return "PASSWORD";
    }

    @Override
    public LoginParamAdapter resolve(LoginParamAdapter loginParam) throws AuthenticationException {
        return loginParam;
    }
}
