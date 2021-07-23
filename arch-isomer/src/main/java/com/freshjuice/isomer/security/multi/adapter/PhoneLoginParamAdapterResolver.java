package com.freshjuice.isomer.security.multi.adapter;

import com.freshjuice.isomer.security.entity.User;
import org.springframework.security.core.AuthenticationException;

public class PhoneLoginParamAdapterResolver extends AbstractLoginParamAdapterResolver {

    public PhoneLoginParamAdapterResolver(LoginParamAdapterService loginParamService) {
        super(loginParamService);
    }

    @Override
    protected String getSupportsTag() {
        return "PHONE";
    }

    @Override
    public LoginParamAdapter resolve(LoginParamAdapter loginParam) throws AuthenticationException {
        User user = loginParamService.getUserByPhone(loginParam.getPhone());
        if(user == null) throw new PhoneNotFoundAdapterException("手机号,["+loginParam.getPhone()+"]不存在");
        loginParamService.checkSmsCode(loginParam.getPhone(), loginParam.getSmsCode());
        loginParam.setUserName(user.getUserName());
        loginParam.setPassword(user.getPassword());
        return loginParam;
    }

}
