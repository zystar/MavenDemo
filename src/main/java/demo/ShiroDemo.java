package demo;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.ExpiredCredentialsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.Factory;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.util.SimpleByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author STAR
 * 参考：https://www.oschina.net/code/snippet_571282_35758
 */
public class ShiroDemo
{
	private static Logger logger = LoggerFactory.getLogger(ShiroDemo.class); 

	public static void main(String[] args)
	{
		//获取SecurityManagerFactory工厂，也可以使用数据库来获取，这里使用ini文件来初始化
		Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");

		//得到SecurityManger，并且进行绑定到SecuriUtils
		SecurityManager securityManager = (SecurityManager)factory.getInstance();
		SecurityUtils.setSecurityManager(securityManager);

		//得到Subject及创建用户名/密码身份验证Token（用户身份或者是凭证）
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken("lh", "123123");

		try
		{
			subject.login(token);
		}

		catch (UnknownAccountException uae)
		{
			logger.info("用户名为【" + token.getPrincipal() + "】不存在");
		}
		catch (IncorrectCredentialsException ice)
		{
			logger.info("用户名为【 " + token.getPrincipal() + " 】密码错误！");
		}
		catch (LockedAccountException lae)
		{
			logger.info("用户名为【" + token.getPrincipal() + " 】的账户锁定，请联系管理员。");
		}
		catch(DisabledAccountException dax)
		{
			logger.info("用户名为:【" + token.getHost() + "】用户已经被禁用.");
		}
		catch(ExcessiveAttemptsException eae)
		{
			logger.info("用户名为:【" + token.getHost() + "】的用户登录次数过多，有暴力破解的嫌疑.");
		}
		catch(ExpiredCredentialsException eca)
		{
			logger.info("用户名为:【" + token.getHost() + "】用户凭证过期.");
		}
		catch (AuthenticationException ae)
		{
			logger.info("用户名为:【" + token.getHost() + "】用户验证失败.");
		}
		catch(Exception e)
		{
			logger.info("别的异常信息。。。。具体查看继承关系");
		}


		//////////////////////////////////////////////////////////////
		logger.info("用户名 【" + subject.getPrincipal() + "】密码：【" + subject.getPrincipal() + "】登录成功.");

		if(subject.hasRole("user"))
		{
			logger.info("拥有【user】角色。");
		}
		else
		{
			logger.info("不存在user权限。");
		}

		try
		{
			subject.checkPermission("users:create:del:upd");
		}
		catch (AuthorizationException e)
		{
			e.printStackTrace();
		}


		if(subject.isPermitted("users:create"))
		{
			logger.info("拥有【users:del】删除权限");
		}
		else
		{
			logger.info("不存在【users:del】删除权限");
		}

		logger.info(subject.getPrincipal().toString() + "用户 登录状态：" + subject.isAuthenticated());

		subject.logout();

		//对密码md5加密,并且进行私盐
		String baseCode = new Md5Hash("123123", "1223").toString();
		// System.out.println(baseCode);

		/**使用私盐和公盐进行加密****/
		DefaultHashService hashService = new DefaultHashService(); //默认算法SHA-512
		hashService.setHashAlgorithmName("SHA-384");
		hashService.setPrivateSalt(new SimpleByteSource("zhongguo")); //私盐，默认无
		hashService.setRandomNumberGenerator(new SecureRandomNumberGenerator());//用于生成公盐。默认就是这个
		hashService.setHashIterations(2); //生成Hash值的迭代次数
		hashService.setGeneratePublicSalt(true); //是否生成公盐，默认false


		HashRequest request = new HashRequest.Builder()
		.setAlgorithmName("MD5").setSource(ByteSource.Util.bytes("Rayn123"))
		.setSalt(ByteSource.Util.bytes("123123")).setIterations(2).build();



		String hex = hashService.computeHash(request).toHex();


		System.out.println(hex);

	}
}
