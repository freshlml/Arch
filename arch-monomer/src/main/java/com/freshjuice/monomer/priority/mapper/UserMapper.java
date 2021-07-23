package com.freshjuice.monomer.priority.mapper;

import com.freshjuice.monomer.priority.entity.User;

public interface UserMapper {
    User getUserByName(String username);
    User getUserByPhone(String phone);
	User getUserById(Long id);
}
