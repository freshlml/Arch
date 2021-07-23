package com.freshjuice.isomer.security.multi.rep.userdetails;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.freshjuice.isomer.security.entity.ResourcePriority;
import com.freshjuice.isomer.security.entity.RoleResource;
import com.freshjuice.isomer.security.entity.User;
import com.freshjuice.isomer.security.entity.UserRole;
import com.freshjuice.isomer.security.service.ResourcePriorityService;
import com.freshjuice.isomer.security.service.RoleResourceService;
import com.freshjuice.isomer.security.service.UserRoleService;
import com.freshjuice.isomer.security.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class RepUserDetailsService implements UserDetailsService {

    private static final String prefix = "ROLE_";

    @Autowired
    private UserService userService;

    @Autowired
    private UserRoleService userRoleService;

    @Autowired
    private RoleResourceService roleResourceService;

    @Autowired
    private ResourcePriorityService resourcePriorityService;

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
            RepUserDetails details = new RepUserDetails();
            details.setUserName(user.getUserName());
            details.setPassword(user.getPassword());

            List<UserRole> userRoles = userRoleService.list(new LambdaQueryWrapper<UserRole>().select(UserRole::getRoleId).eq(UserRole::getUserId, user.getId()));
            List<Long> roleIds = userRoles.stream().map(userRole -> userRole.getRoleId()).collect(Collectors.toList());
            if(roleIds == null || roleIds.size() == 0) {
                details.setPermission(new ArrayList<>());
                return details;
            }
            List<RoleResource> roleResources = roleResourceService.list(new LambdaQueryWrapper<RoleResource>().select(RoleResource::getResourceId).in(RoleResource::getRoleId, roleIds));
            List<Long> ids = roleResources.stream().map(roleResource -> roleResource.getResourceId()).distinct().collect(Collectors.toList());
            if(ids == null || ids.size() == 0) {
                details.setPermission(new ArrayList<>());
                return details;
            }
            Collection<ResourcePriority> rs = resourcePriorityService.listByIds(ids);
            List<RepPermission> permissions = rs.stream().map(r -> RepPermission.builder().permission(r.getCode()).build()).collect(Collectors.toList());

            details.setPermission(permissions);
            return details;
        } catch (Exception e) {
            log.error("获取用户信息失败, {}, {}", username, e.getMessage());
            throw new UsernameNotFoundException("查找用户["+username+"]失败");
        }
    }
}
