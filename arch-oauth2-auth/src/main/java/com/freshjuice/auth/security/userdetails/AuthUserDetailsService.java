package com.freshjuice.auth.security.userdetails;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.freshjuice.auth.security.entity.User;
import com.freshjuice.auth.security.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import java.util.ArrayList;

@Slf4j
public class AuthUserDetailsService implements UserDetailsService {

    private static final String prefix = "ROLE_";

    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = null;
        try {
            user = userService.getOne(new LambdaQueryWrapper<User>().select(User::getId, User::getUserName, User::getPassword, User::getPhone).eq(User::getUserName, username));
        } catch (Exception e) {
            log.error(e.getMessage());
            user = null;
        }
        if(user == null) throw new UsernameNotFoundException("用户["+username+"]未找到");

        try {
            AuthUserDetails details = new AuthUserDetails();
            details.setUserName(user.getUserName());
            details.setPassword(user.getPassword());
            //TODO
            details.setPermission(new ArrayList<>());

            return details;
        } catch (Exception e) {
            log.error("获取用户信息失败, {}, {}", username, e.getMessage());
            throw new UsernameNotFoundException("查找用户["+username+"]失败");
        }
    }
}
