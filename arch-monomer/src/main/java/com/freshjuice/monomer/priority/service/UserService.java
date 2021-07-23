package com.freshjuice.monomer.priority.service;

import com.freshjuice.monomer.priority.entity.User;

public interface UserService {
    User getUserByName(String username);
    User getUserByPhone(String phone);
	User getUserById(Long id);
}
