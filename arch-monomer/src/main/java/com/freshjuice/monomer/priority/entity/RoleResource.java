package com.freshjuice.monomer.priority.entity;

import com.freshjuice.monomer.common.entity.BaseEntity;
import lombok.Data;

@Data
public class RoleResource extends BaseEntity {
    private Long roleId;
    private Long resourceId;
    private String remark;
}
