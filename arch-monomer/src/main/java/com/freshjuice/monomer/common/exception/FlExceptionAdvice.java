package com.freshjuice.monomer.common.exception;

import com.freshjuice.monomer.common.utils.FlWebUtils;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@ControllerAdvice
public class FlExceptionAdvice {
	private Logger logger = LoggerFactory.getLogger(FlExceptionAdvice.class);
    @ExceptionHandler(value=Exception.class)
	public ModelAndView exy(Exception ex,
                            HttpServletRequest request, HttpServletResponse response) {

		boolean isJson = FlWebUtils.fJsonRequestAcceptExtend(request);
		String errMessage = "系统异常";
		if(UnauthorizedException.class == ex.getClass()) {
			errMessage = "无权限";
		} else if(UnauthenticatedException.class == ex.getClass()) {
			errMessage = "check权限前为Authentication";
		} else if(ex instanceof FlRootException) {
			errMessage = ex.getMessage();
		}
		logger.error(ex.getMessage());
		if(isJson) {
			ModelAndView mv = new ModelAndView(new MappingJackson2JsonView());
			mv.addObject("code", "500");
			mv.addObject("message", errMessage);
			return mv;
		} else {
			ModelAndView mv = new ModelAndView("redirect:/error");
			mv.addObject("errorMsg", errMessage);
			return mv;
		}
	}
}
