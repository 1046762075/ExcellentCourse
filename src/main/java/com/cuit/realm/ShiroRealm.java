package com.cuit.realm;

import javax.annotation.Resource;

import com.cuit.controller.NewsController;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import com.cuit.domain.User;
import com.cuit.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ShiroRealm extends AuthorizingRealm {

	private Logger log = LoggerFactory.getLogger(AuthorizingRealm.class);
	
	@Resource
	private UserService us;

	/**
	 * 为当限前登录的用户授予角色和权
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String username = (String) principals.getPrimaryPrincipal();

		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();

		try {
			authorizationInfo.setRoles(us.getRolesByUsername(username));
			authorizationInfo.setStringPermissions(us.getPermissionsByUsername(username));
			log.info("\n此用户的roles: " + authorizationInfo.getRoles() + "\t此用户的permissions: " + authorizationInfo.getStringPermissions());
		} catch (Exception e) { }
		return authorizationInfo;
	}

	/**
	 * 验证当前登录的用户
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		SimpleAuthenticationInfo authenticationInfo;
		UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
		String username = usernamePasswordToken.getUsername();
		User user = us.getUserByUsername(username);
		if (user != null) {
			log.debug("\n数据库存在此用户:" + username);
			authenticationInfo = new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), this.getName());
			return authenticationInfo;
		} else {
			log.info("\n用户认证未查询到");
			throw new AuthenticationException();
		}
	}
}
