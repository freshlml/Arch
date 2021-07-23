package com.freshjuice.monomer.priority.service;

import com.freshjuice.monomer.priority.entity.UserRole;

import java.util.List;

public interface UserRoleService {
    List<UserRole> listByUserId(Long id);
}
