package com.freshjuice.auth.security.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.freshjuice.auth.security.entity.Oauth2Client;
import com.freshjuice.auth.security.mapper.Oauth2ClientMapper;
import com.freshjuice.auth.security.service.Oauth2ClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class Oauth2ClientServiceImpl extends ServiceImpl<Oauth2ClientMapper, Oauth2Client> implements Oauth2ClientService {

	@Autowired
	private Oauth2ClientMapper oauth2ClientMapper;


	@Override
	public Oauth2Client getClientByClientId(String clientId) {
		return this.getOne(new LambdaQueryWrapper<Oauth2Client>().eq(Oauth2Client::getClientId, clientId));
	}
}
