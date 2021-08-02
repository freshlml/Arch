package com.freshjuice.auth.security.entity;

import com.freshjuice.auth.common.entity.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User extends BaseEntity<Long> {
    private String userName;
    private String password;
    private String phone;
}
