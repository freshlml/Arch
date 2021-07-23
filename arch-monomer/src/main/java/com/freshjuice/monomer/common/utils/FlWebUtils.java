package com.freshjuice.monomer.common.utils;

import org.apache.shiro.web.util.WebUtils;

import javax.servlet.http.HttpServletRequest;

public class FlWebUtils {

	public static final String FUL_JSON_Mark = "FUL_JSON_Mark";
	/**
	 * 根据request.getHeader判断是否是ajax请求
	 * @param request
	 * @return
	 */
	public static boolean fJsonRequest(HttpServletRequest request) {
		String requestType = request.getHeader("X-Requested-With");
		if("XMLHttpRequest".equals(requestType)) return true;
		return false;
	}

	public static boolean fJsonRequestExtend(HttpServletRequest request) {
		String fAjax = (String) request.getAttribute(FUL_JSON_Mark);
		if(fAjax != null) {
			return "json".equals(fAjax)?true:false;
		} else {
			return fJsonRequest(request);
		}
	}
	
	/**
	 * 根据请求的accept做判断
	 * 1、如果accept中存在text/html，表示是html请求返回页面
	 * 否则返回json
	 * 
	 * 注： $.load调用底层使用的是$.ajax:dataType="html"
	 * 
	 */
	public static boolean fJsonRequestAccept(HttpServletRequest request) {
		String accept = request.getHeader("Accept");
		if(accept != null && accept.contains("text/html")) return false;
		return true;
	}

	/**
	 * 增加前置判断request.getAttribute(FUL_JSON_Mark)
	 * @param request
	 * @return
	 */
	public static boolean fJsonRequestAcceptExtend(HttpServletRequest request) {
		String fAjax = (String) request.getAttribute(FUL_JSON_Mark);
		if(fAjax != null) {
			return "json".equals(fAjax)?true:false;
		} else {
			return fJsonRequestAccept(request);
		}
	}

	/**
	 * 获取requestURI exclude Context Path
	 * @param request
	 * @return
	 */
	public static String getPathWithinApplication(HttpServletRequest request) {
		return WebUtils.getPathWithinApplication(request);
	}

	/**
	 * 获取 context path
	 * @param request
	 * @return
	 */
	public static String getContextPath(HttpServletRequest request) {
		return WebUtils.getContextPath(request);
	}

	/**
	 * requestURI
	 * @param request
	 * @return
	 */
	public static String getRequestUri(HttpServletRequest request) {
		return WebUtils.getRequestUri(request);
	}
}
