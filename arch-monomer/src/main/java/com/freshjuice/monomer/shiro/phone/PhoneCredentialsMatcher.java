package com.freshjuice.monomer.shiro.phone;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

public class PhoneCredentialsMatcher extends SimpleCredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {

        Object frontEndCredentials = this.getCredentials(info);
        Object backEndCredentials = "123456"; //取手机号的creditCode

        return this.equals(frontEndCredentials, backEndCredentials);
    }
}
