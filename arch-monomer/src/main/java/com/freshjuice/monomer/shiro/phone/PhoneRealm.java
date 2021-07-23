package com.freshjuice.monomer.shiro.phone;

import com.freshjuice.monomer.common.enums.PrincipalEnum;
import com.freshjuice.monomer.priority.entity.ResourcePriority;
import com.freshjuice.monomer.priority.entity.User;
import com.freshjuice.monomer.priority.service.ResourcePriorityService;
import com.freshjuice.monomer.priority.service.UserService;
import com.freshjuice.monomer.shiro.UserPrincipal;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.List;
import java.util.stream.Collectors;

public class PhoneRealm extends AuthorizingRealm {

    private UserService userService;
    private ResourcePriorityService resourcePriorityService;
    public UserService getUserService() {
        return userService;
    }

    public ResourcePriorityService getResourceService() {
        return resourcePriorityService;
    }

    public void setResourceService(ResourcePriorityService resourcePriorityService) {
        this.resourcePriorityService = resourcePriorityService;
    }

    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        UserPrincipal userPrincipal = (UserPrincipal) principalCollection.getPrimaryPrincipal(); //only one principal exists

        //String principal = (String) paramPrincipalCollection.getPrimaryPrincipal();
        //if(userPrincipal == null) return null;  //如果无认证信息，但是该资源进行Authorize(这当属不正常情况)
        if(PrincipalEnum.PHONE.getValue().equals(userPrincipal.getType().getValue())) {
            List<ResourcePriority> resources = resourcePriorityService.getResourcePriorities(userPrincipal.getUsername());
            List<String> permissions = resources.stream().map(r -> r.getCode()).collect(Collectors.toList());

            SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
            simpleAuthorizationInfo.addStringPermissions(permissions);

            return simpleAuthorizationInfo;
        }
        return null;

    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token.getClass() == PhoneToken.class;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        PhoneToken token = (PhoneToken) authenticationToken;
        String phone = token.getPhone();

        User user = userService.getUserByPhone(phone);

        if(user == null) throw new UnknownAccountException("手机号: [" + phone + "]不存在");

        return new SimpleAuthenticationInfo(new UserPrincipal(user.getUserName(), user.getPhone(), PrincipalEnum.PHONE),
                token.getPhoneCredit(),
                this.getName());

    }
}
