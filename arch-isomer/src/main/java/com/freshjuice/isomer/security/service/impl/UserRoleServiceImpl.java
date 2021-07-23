package com.freshjuice.isomer.security.service.impl;


import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.freshjuice.isomer.security.entity.UserRole;
import com.freshjuice.isomer.security.mapper.UserRoleMapper;
import com.freshjuice.isomer.security.service.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserRoleServiceImpl extends ServiceImpl<UserRoleMapper, UserRole> implements UserRoleService {

    @Autowired
    private UserRoleMapper userRoleMapper;


}
