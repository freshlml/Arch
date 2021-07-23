package com.freshjuice.isomer.security.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.freshjuice.isomer.security.entity.RoleResource;
import com.freshjuice.isomer.security.mapper.RoleResourceMapper;
import com.freshjuice.isomer.security.service.RoleResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class RoleResourceServiceImpl extends ServiceImpl<RoleResourceMapper, RoleResource> implements RoleResourceService {

    @Autowired
    private RoleResourceMapper roleResourceMapper;

}
