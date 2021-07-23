package com.freshjuice.isomer.security.multi.adapter;

import com.freshjuice.isomer.security.entity.User;

public interface LoginParamAdapterService {
    User getUserByPhone(String phone);
    public void checkSmsCode(String phone, String code);
}
