package com.sy.shiro.shirodemo;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

	private static final transient Logger log = LoggerFactory.getLogger(Main.class);

	public static void main(String[] args) {
		// 获取SecurityManager的实例
		Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-realm.ini");
		SecurityManager securityManager = factory.getInstance();

		SecurityUtils.setSecurityManager(securityManager);

		Subject currenUser = SecurityUtils.getSubject();

		// 如果还未认证
		if (!currenUser.isAuthenticated()) {
			UsernamePasswordToken token = new UsernamePasswordToken("admin", "123");
			token.setRememberMe(true);
			try {
				currenUser.login(token);
			} catch (UnknownAccountException uae) {
				log.info("没有该用户： " + token.getPrincipal());
			} catch (IncorrectCredentialsException ice) {
				log.info(token.getPrincipal() + " 的密码不正确!");
			} catch (LockedAccountException lae) {
				log.info(token.getPrincipal() + " 被锁定 ，请联系管理员");
			} catch (AuthenticationException ae) {
				// 其他未知的异常
			}
		}

		if (currenUser.isAuthenticated())
			log.info("用户 " + currenUser.getPrincipal() + " 登录成功");

		// 是否有role1这个角色
		if (currenUser.hasRole("role1")) {
			log.info("有角色role1");
		} else {
			log.info("没有角色role1");
		}
		// 是否有对打印机进行打印操作的权限
		if (currenUser.isPermitted("printer:print")) {
			log.info("可以对打印机进行打印操作");
		} else {
			log.info("不可以对打印机进行打印操作");
		}
	}

}
