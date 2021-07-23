package com.freshjuice.monomer.priority.service.impl;

import com.freshjuice.monomer.priority.entity.User;
import com.freshjuice.monomer.priority.mapper.UserMapper;
import com.freshjuice.monomer.priority.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private UserMapper userMapper;
	@Autowired
	private RedisTemplate<String, Object> redisTemplate;


	@Override
	public User getUserByName(String username) {
		User user = (User) redisTemplate.opsForValue().get("user:" + username);
		if (user != null) return user;
		User userDb = userMapper.getUserByName(username);
		redisTemplate.opsForValue().set("user:" + username, userDb);
		return userDb;
	}

	@Override
	public User getUserByPhone(String phone) {
		User user = (User) redisTemplate.opsForValue().get("user:" + phone);
		if(user != null) return user;
		User userDb = userMapper.getUserByPhone(phone);
		redisTemplate.opsForValue().set("user:" + phone, userDb);
		return userDb;
	}

	@Override
	public User getUserById(Long id) {
		User user = (User) redisTemplate.opsForValue().get("user:" + id);
		if(user != null) return user;
		User userDb = userMapper.getUserById(id);
		redisTemplate.opsForValue().set("user:" + id, userDb);
		return userDb;
	}


	/*
	 * spring-data-redis 抽象目前遇到的问题：
	 * 1 getUserById 根据id缓存User,getUserByName 根据name缓存User （产生大量冗余？）
	 *   这样将存在两个相同value的key,则当User中某些字段更新时,要同时删除这两个key （如何同时删除这两个key？）
	 *   如果只保存一个value为User,那么key又如何设置呢？
	 * 2 针对"缓存从数据库中查询的数据"，这和mybatis二级缓存没区别
	 * 3 spring-data-redis抽象只提供了string格式api支持
	 *
	 * 按照spring-data-redis抽象的逻辑：生成key，将result缓存
	 * 应对service中茫茫多种类方法时，显得不太能统一
	 *
	 * 目前的结论是：对需要缓存的数据使用redisTemplate
	 */
	/*@Cacheable(value="user", key="#root.args[0]")
	@Override
	public User getUserById(String id) {
		return userDao.getUserById(id);
	}
	public void addUser(User user) {
	}
	public void updateUser(User user) {
	}
	@CacheEvict(value="user")
	@Override
	public void removeUserById(String id) {
		userDao.delUserById(id);
	}*/

}
