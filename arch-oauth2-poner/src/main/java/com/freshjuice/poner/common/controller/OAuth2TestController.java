package com.freshjuice.poner.common.controller;

import com.freshjuice.poner.common.vo.JsonResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("oauth2")
public class OAuth2TestController {

    @PostMapping("post")
    public JsonResult post() {
        return JsonResult.buildSuccessResult("oauth2 post");
    }

}
