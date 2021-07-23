package com.freshjuice.monomer.priority.service;

import com.freshjuice.monomer.priority.entity.RoleResource;

import java.util.List;

public interface RoleResourceService {

    List<RoleResource> listByRoleIds(List<Long> roleIds);
}
