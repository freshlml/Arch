package com.freshjuice.isomer.security.multi.rep;

import lombok.Data;

@Data
public class LoginParam {
    private String userName;
    private String password;
    private String rememberMe; //on yes true 1 and the other side
    private String type; //PASSWORD,PHONE
    private String phone;
    private String smsCode;
}
