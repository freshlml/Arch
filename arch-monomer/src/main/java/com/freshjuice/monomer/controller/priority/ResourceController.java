package com.freshjuice.monomer.controller.priority;

import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@Controller
public class ResourceController {
	
	@SuppressWarnings("unused")
	private Logger logger = LoggerFactory.getLogger(ResourceController.class);
	
	@RequestMapping("/pr1")
	@RequiresPermissions(value={"pr1"})
	public ModelAndView pr1() {
		ModelAndView modelAndView = new ModelAndView();
		modelAndView.setViewName("WEB-INF/jsps/pr1");
		return modelAndView;
	}
	
	@RequestMapping("/pr1-c1")
	public ModelAndView pr1_c1() {
		ModelAndView modelAndView = new ModelAndView();
		modelAndView.setViewName("WEB-INF/jsps/pr1-c1");
		return modelAndView;
	}
	
	@RequestMapping("/pr1-c2")
	@RequiresPermissions(value={"pr1-c2"})
	public ModelAndView pr1_c2() {
		ModelAndView modelAndView = new ModelAndView();
		modelAndView.setViewName("WEB-INF/jsps/pr1-c2");
		return modelAndView;
	}
	
	@RequestMapping("/pr2")
	@RequiresPermissions(value={"pr2"})
	public ModelAndView pr2() {
		ModelAndView modelAndView = new ModelAndView();
		modelAndView.setViewName("WEB-INF/jsps/pr2");
		return modelAndView;
	}
	
	@RequestMapping("/pr3")
	@ResponseBody
	public Map<String, String> pr3() {
		Map<String, String> map = new HashMap<String, String>();
		map.put("pr3", "pr3");
		return map;
	}

}
