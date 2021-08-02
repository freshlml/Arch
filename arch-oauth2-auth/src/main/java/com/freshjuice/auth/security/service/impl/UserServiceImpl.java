package com.freshjuice.auth.security.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.freshjuice.auth.security.entity.User;
import com.freshjuice.auth.security.mapper.UserMapper;
import com.freshjuice.auth.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

	@Autowired
	private UserMapper userMapper;

}
