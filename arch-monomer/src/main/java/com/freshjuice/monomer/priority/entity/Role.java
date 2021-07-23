package com.freshjuice.monomer.priority.entity;

import com.freshjuice.monomer.common.entity.BaseEntity;
import lombok.Data;

@Data
public class Role extends BaseEntity {
    private String roleCode;
    private String roleName;
}
