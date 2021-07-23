package com.freshjuice.monomer.controller.index;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;


@Controller
public class IndexController {
	
	@SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(IndexController.class);
	

	@RequestMapping(path={"/", "/index"}, method={RequestMethod.GET})
	public ModelAndView index() {
		ModelAndView mv = new ModelAndView("index");
		Subject subject = SecurityUtils.getSubject();
		Object principal = null;
		if(subject != null && subject.isAuthenticated()) {
			principal = subject.getPrincipal();
		}
		mv.addObject("pricipal", principal);
		return mv;
	}
	
	@RequestMapping("/error")
	public ModelAndView err(String errorMsg) {
		ModelAndView mv = new ModelAndView("error");
		mv.addObject("errorMsg", errorMsg);
		return mv;
	}

}
