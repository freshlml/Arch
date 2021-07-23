package com.freshjuice.monomer.priority.service.impl;

import com.freshjuice.monomer.priority.entity.RoleResource;
import com.freshjuice.monomer.priority.mapper.RoleResourceMapper;
import com.freshjuice.monomer.priority.service.RoleResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoleResourceServiceImpl implements RoleResourceService {

    @Autowired
    private RoleResourceMapper roleResourceMapper;

    @Override
    public List<RoleResource> listByRoleIds(List<Long> roleIds) {
        return roleResourceMapper.listByRoleIds(roleIds);
    }
}
