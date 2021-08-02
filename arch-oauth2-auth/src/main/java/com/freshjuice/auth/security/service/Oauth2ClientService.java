package com.freshjuice.auth.security.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.freshjuice.auth.security.entity.Oauth2Client;

public interface Oauth2ClientService extends IService<Oauth2Client> {
    Oauth2Client getClientByClientId(String clientId);
}
