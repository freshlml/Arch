package com.freshjuice.monomer.controller.login;

import com.freshjuice.monomer.common.utils.FlWebUtils;
import com.freshjuice.monomer.shiro.phone.PhoneToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;


@Controller
public class LoginController {
	private Logger logger = LoggerFactory.getLogger(LoginController.class);
	
	//login 跳转
	@RequestMapping("/login")
	public ModelAndView login(HttpServletRequest request) {
		logger.debug("login跳转");
		ModelAndView modelAndView = new ModelAndView();
		modelAndView.setViewName("WEB-INF/jsps/login");
		modelAndView.addObject("errorMsg", request.getParameter("errorMsg"));
		return modelAndView;
	}
	
	//login 登陆确认
	@RequestMapping("/loginConfirm")
	public ModelAndView loginConfirm(String username, String password, String rememberMe,
			HttpServletRequest request, HttpServletResponse response) {
		
		UsernamePasswordToken token = new UsernamePasswordToken(username, password, WebUtils.isTrue(request, rememberMe), request.getRemoteHost());
		try {
			Subject subject = SecurityUtils.getSubject();
			subject.login(token);
			//authentication success
			//返回json格式数据，提示authentication成功
			if(FlWebUtils.fJsonRequestAcceptExtend(request)) {
				ModelAndView mv = new ModelAndView(new MappingJackson2JsonView());
    			mv.addObject("code", "200");
    			mv.addObject("message", "authentication 成功!!!");
    			return mv;
			} else {
				//否则，重定向到主页 （如果页面传递了重定向地址，则重定向到该地址）
				ModelAndView modelAndView = new ModelAndView();
        		modelAndView.setViewName("redirect:/index");
        		return modelAndView;
			}
		} catch(AuthenticationException e) { //authentication failure
			String errorMsg;
			if (UnknownAccountException.class == e.getClass()) {
                errorMsg = "["+ username + "]账号不存在";
            } else if (IncorrectCredentialsException.class == e.getClass()) {
                errorMsg = "用户名或密码错误";
            } else {
				errorMsg = "认证失败";
            }
			//返回json格式数据，提示authentication失败
			if(FlWebUtils.fJsonRequestAcceptExtend(request)) {
				ModelAndView mv = new ModelAndView(new MappingJackson2JsonView());
    			mv.addObject("code", "403");
    			mv.addObject("message", errorMsg);
    			return mv;
			} else { //否则，重定向到login页面，提示错误信息
				ModelAndView modelAndView = new ModelAndView();
        		modelAndView.setViewName("redirect:/login");
        		modelAndView.addObject("errorMsg", errorMsg);
        		return modelAndView;
			}
			
		} catch(Exception e) {
			ModelAndView mv = new ModelAndView("error");
			mv.addObject("errorMsg", e.getMessage());
			return mv;
		}
		
	}
	
	//手机号验证码
	@RequestMapping("/phoneLogin/getCredit")
	@ResponseBody
	public Map<String, String> phoneGetCredit(String phoneNum) {
		Map<String, String> ret = new HashMap<String, String>();
		//手机号验证码
		ret.put("code", "200");
		ret.put("message", phoneNum + "已生成验证码: 123456");
		return ret;
	}
	
	//phone login登陆确认
	@RequestMapping("/phoneLogin/login")
	public ModelAndView phoneLogin(String phoneNum, String phoneCredit, String rememberMe,
								   HttpServletRequest request, HttpServletResponse response) {

		PhoneToken phoneToken = new PhoneToken(null, null, WebUtils.isTrue(request, rememberMe), request.getRemoteHost(), phoneNum, phoneCredit);
		try {
			Subject subject = SecurityUtils.getSubject();
			subject.login(phoneToken);
			//authentication success
			//返回json格式数据，提示authentication成功
			if(FlWebUtils.fJsonRequestAcceptExtend(request)) {
				ModelAndView mv = new ModelAndView(new MappingJackson2JsonView());
				mv.addObject("code", "200");
				mv.addObject("message", "authentication 成功!!!");
				return mv;
			} else {
				//否则，重定向到主页 （如果页面传递了重定向地址，则重定向到该地址）
				ModelAndView modelAndView = new ModelAndView();
				modelAndView.setViewName("redirect:/index");
				return modelAndView;
			}
		} catch(AuthenticationException e) { //authentication failure
			String errorMsg;
			if (UnknownAccountException.class == e.getClass()) {
				errorMsg = "["+ phoneNum + "]手机号不存在";
			} else if (IncorrectCredentialsException.class == e.getClass()) {
				errorMsg = "验证码错误";
			} else {
				errorMsg = "认证失败";
			}
			//如果该登陆确认请求是ajax请求，则返回json格式数据，提示authentication失败
			if(FlWebUtils.fJsonRequestAcceptExtend(request)) {
				ModelAndView mv = new ModelAndView(new MappingJackson2JsonView());
				mv.addObject("code", "403");
				mv.addObject("message", errorMsg);
				return mv;
			} else { //否则，重定向到login页面，提示错误信息
				ModelAndView modelAndView = new ModelAndView();
				modelAndView.setViewName("redirect:/login");
				modelAndView.addObject("errorMsg", errorMsg);
				return modelAndView;
			}

		} catch(Exception e) {
			ModelAndView mv = new ModelAndView("error");
			mv.addObject("errorMsg", e.getMessage());
			return mv;
		}

	}
}
