package com.freshjuice.isomer.security.entity;

import com.freshjuice.isomer.common.entity.BaseEntity;
import lombok.Data;

@Data
public class Role extends BaseEntity<Long> {
    private String roleCode;
    private String roleName;
}
