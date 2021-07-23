package com.freshjuice.isomer.security.multi.adapter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractLoginParamAdapterResolver implements LoginParamAdapterResolver {

    private Logger log = LoggerFactory.getLogger(AbstractLoginParamAdapterResolver.class);
    protected LoginParamAdapterService loginParamService;

    public AbstractLoginParamAdapterResolver(LoginParamAdapterService loginParamService) {
        this.loginParamService = loginParamService;
    }

    public boolean supports(LoginParamAdapter loginParam) {
        if(loginParam == null) {
            log.warn("loginParam is null");
            return false;
        }
        return getSupportsTag().equals(loginParam.getType());
    }

    protected abstract String getSupportsTag();

}
