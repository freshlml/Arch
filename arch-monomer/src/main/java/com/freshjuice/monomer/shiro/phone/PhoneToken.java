package com.freshjuice.monomer.shiro.phone;

import org.apache.shiro.authc.UsernamePasswordToken;

public class PhoneToken extends UsernamePasswordToken {
    private String phone;
    private String phoneCredit;

    public PhoneToken(String username, String password, boolean rememberMe, String host, String phone, String phoneCredit) {
        super(username, password, rememberMe, host);
        this.phone = phone;
        this.phoneCredit = phoneCredit;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getPhoneCredit() {
        return phoneCredit;
    }

    public void setPhoneCredit(String phoneCredit) {
        this.phoneCredit = phoneCredit;
    }
}
