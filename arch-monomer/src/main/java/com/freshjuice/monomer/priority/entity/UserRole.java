package com.freshjuice.monomer.priority.entity;

import com.freshjuice.monomer.common.entity.BaseEntity;
import lombok.Data;

@Data
public class UserRole extends BaseEntity {
    private Long userId;
    private Long roleId;
    private String remark;
}
