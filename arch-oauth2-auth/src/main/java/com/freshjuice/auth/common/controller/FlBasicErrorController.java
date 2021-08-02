package com.freshjuice.auth.common.controller;

import com.freshjuice.auth.common.enums.JsonResultEnum;
import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.ModelAndView;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * servlet container中执行异常，转发到/error ，TODO,问题是转发到/error也要走filter，因此/error不应该走filter??
 *   StandardHostValue.class
 *    //发现tomcat中的errorPage
 *    ErrorPage errorPage = context.findErrorPage(statusCode);
 *         if (errorPage == null) {
 *             //返回spring boot中的errorPage， 这里返回   /error
 *             errorPage = context.findErrorPage(0);
 *         }
 *         //转发到 /error，/error还是要走filter，所以这里仍然报异常，这里的异常，到ErrorReportValue,ErrorReportValue中直接拼接一个串html返回
 *         RequestDispatcher.forward(/error);
 *
 * 进入到controller即之后组件中执行的异常: FlExceptionHandler
 */
@Controller
public class FlBasicErrorController extends BasicErrorController {

	public FlBasicErrorController() {
        super(new DefaultErrorAttributes(), new ErrorProperties());
    }
	
	//json
    @Override
    public ResponseEntity<Map<String, Object>> error(HttpServletRequest request) {
        Map<String, Object> body = getErrorAttributes(request, /*isIncludeStackTrace(request, MediaType.ALL)*/ErrorAttributeOptions.of(ErrorAttributeOptions.Include.STACK_TRACE));
        HttpStatus status = getStatus(request);
        Map<String, Object> map = new HashMap<>();
        map.put("success", false);
        map.put("code", status!=null ? status.value()+"" : JsonResultEnum.FAIL.getCode());
        map.put("message", "path=["+body.get("path")+"];error=["+body.get("error")+"];msg=["+body.get("message")+"]");
        return new ResponseEntity<>(map, status);
    }
    
    //html
    @Override
    public ModelAndView errorHtml(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(getStatus(request).value());
        Map<String, Object> model = getErrorAttributes(request, /*isIncludeStackTrace(request, MediaType.TEXT_HTML)*/ErrorAttributeOptions.of(ErrorAttributeOptions.Include.STACK_TRACE));
        return new ModelAndView("error", model);
    }
	
}
