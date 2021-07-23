package com.freshjuice.isomer.security.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.freshjuice.isomer.security.entity.Role;
import com.freshjuice.isomer.security.mapper.RoleMapper;
import com.freshjuice.isomer.security.service.RoleService;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceImpl extends ServiceImpl<RoleMapper, Role> implements RoleService {

}
