package com.freshjuice.monomer.redis;

import com.freshjuice.monomer.BaseJunitTest;
import com.freshjuice.monomer.priority.mapper.UserMapper;
import com.freshjuice.monomer.priority.service.UserService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.WebApplicationContext;

public class BaseTest extends BaseJunitTest {

    /**
     * the true service bean 并不是代理对象
     */
    @Autowired
    private UserService userService;
    @Autowired
    private UserMapper userDao;

    @Autowired
    private WebApplicationContext wac;

    @Test
    public void t1() {

    }

}
