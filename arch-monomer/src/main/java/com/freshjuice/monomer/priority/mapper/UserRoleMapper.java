package com.freshjuice.monomer.priority.mapper;

import com.freshjuice.monomer.priority.entity.UserRole;

import java.util.List;

public interface UserRoleMapper {

    List<UserRole> listByUserId(Long id);
}
