package com.freshjuice.monomer.shiro.custom;

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

public class CustomRealm extends AuthorizingRealm {
	
	private UserService userService;
	private ResourcePriorityService resourcePriorityService;
	
	public UserService getUserService() {
		return userService;
	}
	public void setUserService(UserService userService) {
		this.userService = userService;
	}
	public ResourcePriorityService getResourceService() {
		return resourcePriorityService;
	}
	public void setResourceService(ResourcePriorityService resourcePriorityService) {
		this.resourcePriorityService = resourcePriorityService;
	}
	
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection paramPrincipalCollection) {

		UserPrincipal userPrincipal = (UserPrincipal) paramPrincipalCollection.getPrimaryPrincipal(); //only one principal exists

		//String principal = (String) paramPrincipalCollection.getPrimaryPrincipal();
		//if(userPrincipal == null) return null;  //如果无认证信息，但是该资源进行Authorize(这当属不正常情况)
		if(PrincipalEnum.USERNAME.getValue().equals(userPrincipal.getType().getValue())) {
			List<ResourcePriority> resources = resourcePriorityService.getResourcePriorities(userPrincipal.getUsername());
			List<String> permissions = resources.stream().map(r -> r.getCode()).collect(Collectors.toList());

			SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
			simpleAuthorizationInfo.addStringPermissions(permissions);

			return simpleAuthorizationInfo;
		}
		return null;
	}

	/**
	 * super.supports的实现是UsernamePasswordToken及其子类 返回true；这里覆盖默认实现，只处理UsernamePasswordToken
	 */
	@Override
	public boolean supports(AuthenticationToken token) {
		return token.getClass() == UsernamePasswordToken.class;
	}

	/**
	 *
	 * @param token
	 * @return
	 * @throws AuthenticationException
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token)
			throws AuthenticationException {

		UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
		String username = usernamePasswordToken.getUsername();
		User user = userService.getUserByName(username);

		//if(password == null) return null;
		if(user == null) throw new UnknownAccountException("用户名: [" + username + "]不存在");

		return new SimpleAuthenticationInfo(new UserPrincipal(username, user.getPhone(), PrincipalEnum.USERNAME),
				user.getPassword(),
				this.getName());
	}

	

}
