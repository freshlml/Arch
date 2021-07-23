package com.freshjuice.isomer.security.entity;

import com.freshjuice.isomer.common.entity.BaseEntity;
import lombok.Data;

@Data
public class UserRole extends BaseEntity<Long> {
    private Long userId;
    private Long roleId;
    private String remark;
}
