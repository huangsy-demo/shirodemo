package com.sy.shiro.shirodemo;

import java.util.HashSet;
import java.util.Set;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyRealm1 extends AuthorizingRealm {

	private static final transient Logger log = LoggerFactory.getLogger(Main.class);

	/**
	 * 获取身份信息，我们可以在这个方法中，从数据库获取该用户的权限和角色信息
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		log.info("----------doGetAuthorizationInfo方法被调用----------");
		String username = (String) getAvailablePrincipal(principals);
		// 我们可以通过用户名从数据库获取权限/角色信息
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 权限
		Set<String> s = new HashSet<String>();
		s.add("printer:print");
		s.add("printer:query");
		info.setStringPermissions(s);
		// 角色
		Set<String> r = new HashSet<String>();
		r.add("role1");
		info.setRoles(r);

		return info;
	}

	/**
	 * 在这个方法中，进行身份验证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// 用户名
		String username = (String) token.getPrincipal();
		log.info("username:" + username);
		// 密码
		String password = new String((char[]) token.getCredentials());
		log.info("password:" + password);
		// 从数据库获取用户名密码进行匹配，这里为了方面，省略数据库操作
		if (!"admin".equals(username)) {
			throw new UnknownAccountException();
		}
		if (!"123".equals(password)) {
			throw new IncorrectCredentialsException();
		}
		// 身份验证通过,返回一个身份信息
		AuthenticationInfo aInfo = new SimpleAuthenticationInfo(username, password, getName());

		return aInfo;
	}

}
