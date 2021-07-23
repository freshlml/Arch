package com.freshjuice.poner.common.controller;

import com.freshjuice.poner.common.vo.JsonResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/login/oauth2/")
public class LoginForOauth2Controller {


    @GetMapping("github")
    public JsonResult github(HttpServletRequest request) {
        String error = request.getParameter("error");
        if(error != null) {
            return JsonResult.buildFailedResult(request.getParameter("error_description"));
        }
        //获取token

        return JsonResult.buildSuccessResult("github");
    }


}
