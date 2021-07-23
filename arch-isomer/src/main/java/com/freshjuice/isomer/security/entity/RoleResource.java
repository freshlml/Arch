package com.freshjuice.isomer.security.entity;

import com.freshjuice.isomer.common.entity.BaseEntity;
import lombok.Data;

@Data
public class RoleResource extends BaseEntity<Long> {
    private Long roleId;
    private Long resourceId;
    private String remark;
}
