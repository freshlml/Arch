package com.freshjuice.monomer.priority.service.impl;

import com.freshjuice.monomer.priority.entity.UserRole;
import com.freshjuice.monomer.priority.mapper.UserRoleMapper;
import com.freshjuice.monomer.priority.service.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserRoleServiceImpl implements UserRoleService {

    @Autowired
    private UserRoleMapper userRoleMapper;

    @Override
    public List<UserRole> listByUserId(Long id) {
        return userRoleMapper.listByUserId(id);
    }
}
