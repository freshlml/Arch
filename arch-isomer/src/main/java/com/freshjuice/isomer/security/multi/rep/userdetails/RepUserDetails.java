package com.freshjuice.isomer.security.multi.rep.userdetails;

import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

@Setter
public class RepUserDetails implements UserDetails {

    private String password;
    private String userName;
    private List<RepPermission> permission;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permission;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


    @Override
    public boolean equals(Object o) {
        if(this == o) return true;
        if(o == null) return false;
        if(this.getClass() != o.getClass()) return false;
        RepUserDetails that = (RepUserDetails) o;

        boolean flag = this.userName.equals(that.userName);
        return flag;
    }


    @Override
    public int hashCode() {
        int hashCode = Objects.hashCode(userName);
        return hashCode;
    }


}
