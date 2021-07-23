package com.freshjuice.monomer.priority.entity;

import com.freshjuice.monomer.common.entity.BaseEntity;
import lombok.Data;

@Data
public class User extends BaseEntity {
    private String userName;
    private String password;
    private String phone;
}
