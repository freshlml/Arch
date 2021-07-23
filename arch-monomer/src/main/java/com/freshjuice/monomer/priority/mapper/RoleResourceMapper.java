package com.freshjuice.monomer.priority.mapper;

import com.freshjuice.monomer.priority.entity.RoleResource;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface RoleResourceMapper {

    List<RoleResource> listByRoleIds(@Param("roleIds") List<Long> roleIds);
}
