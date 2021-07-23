package com.freshjuice.monomer.shiro.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.monomer.common.utils.FlWebUtils;
import com.freshjuice.monomer.priority.entity.ResourcePriority;
import com.freshjuice.monomer.priority.service.ResourcePriorityService;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Component("flFormAuthenticationFilter")
public class FlFormAuthenticationFilter extends FormAuthenticationFilter {
	
	private static final String loginAssertUrl = "/loginConfirm";  //保存登陆确认地址
	
	private static final String phoneLoginCredit = "/phoneLogin/getCredit";  //手机号登陆时获取手机号验证码
	private static final String phoneLoginUrl = "/phoneLogin/login";         //手机号验证码登陆
	
	public boolean isLoginAssert(String requestUrl) {
		return loginAssertUrl.equals(requestUrl);
	}
	public boolean isPhoneLoginAssert(String requestUrl) {
		return phoneLoginCredit.equals(requestUrl) || phoneLoginUrl.equals(requestUrl);
	}
	
	@Autowired
	private ResourcePriorityService resourcePriorityService;

	@Override
	protected boolean onAccessDenied(ServletRequest request,
			ServletResponse response) throws Exception {
		
		String requestUrl = getPathWithinApplication(request); /* when /ArchMonomor/path and applicationContextName=ArchMonomor,得到/path or when /path and applicationContextName=/,得到/path */
		if (!isLoginRequest(request, response)) { //如果不是登陆请求
			if(isPhoneLoginAssert(requestUrl)) {//如果是手机号登陆获取验证码或者手机号验证码登陆的请求，返回true，直接转发
				return true;
			}
			if(isLoginAssert(requestUrl)) {//如果是登陆确认请求，则直接转发给登陆确认
				return true;
			}
			//如果不是登陆确认请求，根据该请求的url查询该请求对应的资源
			ResourcePriority resource = resourcePriorityService.getByUrl(requestUrl);
			if(resource != null) { //如果该请求对应的resource 不为 null，
				if("0".equals(resource.getAuthIf())) { //如果该请求无需认证
					return true;
				} else if(FlWebUtils.fJsonRequestAcceptExtend((HttpServletRequest) request)) { //如果该请求需要认证，返回json
					response.setCharacterEncoding("UTF-8");
					response.setContentType("application/json; charset=UTF-8");
					Map<String, String> map = new HashMap<String, String>();
					map.put("code", "403");
					map.put("message", "请先登录");
					ObjectMapper objectMapper = new ObjectMapper();
		            response.getWriter().write(objectMapper.writeValueAsString(map));
		            return false;
				} else { //如果该资源需要认证，且不是ajax调用，则重定向登陆页面
					saveRequestAndRedirectToLogin(request, response);
					return false;
				}
			} else { //如果不是登陆请求，且该资源未定义 resource==null,则需要判断该资源是返回json，还是页面请求，然后重定向到资源未定义的错误提示页面或者返回一个json串表示资源未定义
				if(FlWebUtils.fJsonRequestAcceptExtend((HttpServletRequest) request)) {
					response.setCharacterEncoding("UTF-8");
					response.setContentType("application/json; charset=UTF-8");
					Map<String, String> map = new HashMap<String, String>();
					map.put("code", "404");
					map.put("message", "资源未定义");
					ObjectMapper objectMapper = new ObjectMapper();
		            response.getWriter().write(objectMapper.writeValueAsString(map));
				} else {
					//((HttpServletResponse) response).sendRedirect(((HttpServletResponse) response).encodeRedirectURL(request.getServletContext().getContextPath() + "/error?errorMsg=资源未定义"));
					Map<String, String> queryParams = new HashMap<String, String>();
					queryParams.put("errorMsg", "资源未定义");
					WebUtils.issueRedirect(request, response, "/error", queryParams, true, true);
				}
				return false;
			}
		} else {  //是登陆请求,返回true，转发给login，返回登陆页面
			return true;
		}
		
	}
	
}
