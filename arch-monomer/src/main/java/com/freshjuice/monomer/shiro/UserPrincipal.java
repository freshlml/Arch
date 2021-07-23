package com.freshjuice.monomer.shiro;

import com.freshjuice.monomer.common.enums.PrincipalEnum;

import java.io.Serializable;

/**
 * shiro 对principal（用户身份）的封装
 */
public class UserPrincipal implements Serializable {

    private String username; //用户名
    private String phone;    //手机号
    private PrincipalEnum type; //标记用户身份种类

    public UserPrincipal(String username, String phone, PrincipalEnum type) {
        this.username = username;
        this.phone = phone;
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public PrincipalEnum getType() {
        return type;
    }

    public void setType(PrincipalEnum type) {
        this.type = type;
    }
}
