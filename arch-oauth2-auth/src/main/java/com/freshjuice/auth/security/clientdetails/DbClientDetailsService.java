package com.freshjuice.auth.security.clientdetails;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.auth.common.utils.StringUtils;
import com.freshjuice.auth.security.entity.Oauth2Client;
import com.freshjuice.auth.security.service.Oauth2ClientService;
import com.freshjuice.auth.security.userdetails.AuthPermission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DbClientDetailsService implements ClientDetailsService {

    private Logger log = LoggerFactory.getLogger(DbClientDetailsService.class);

    @Autowired
    private Oauth2ClientService oauth2ClientService;  //TODO,依赖于业务服务

    private ObjectMapper objectMapper = new ObjectMapper();

    /*private Supplier<String> secretGenerateStrategy = () -> UUID.randomUUID().toString();

    public void setSecretGenerateStrategy(Supplier<String> secretGenerateStrategy) {
        this.secretGenerateStrategy = secretGenerateStrategy;
    }*/

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        Oauth2Client oauth2Client = null;
        try {
            oauth2Client = oauth2ClientService.getClientByClientId(clientId);
        } catch (Exception e) {
            log.error("查询ClientDetails失败, {}", e);
            throw new ClientRegistrationException("查询ClientDetails失败");
        }
        if(oauth2Client == null) throw new NoSuchClientException("No client with requested id: " + clientId);

        BaseClientDetails result = new BaseClientDetails();
        result.setClientId(oauth2Client.getClientId());
        result.setClientSecret(oauth2Client.getClientSecret());

        List<String> aus = StringUtils.str2List(oauth2Client.getAuthorities(), null);
        List<AuthPermission> authorities = aus.stream().map(au -> AuthPermission.builder().permission(au).build()).collect(Collectors.toList());
        result.setAuthorities(authorities);
        result.setScope(StringUtils.str2List(oauth2Client.getScope(), null));
        result.setResourceIds(StringUtils.str2List(oauth2Client.getResourceIds(), null));
        if(oauth2Client.getAutoApprove() != null && oauth2Client.getAutoApprove().equals(1)) {
            result.setAutoApproveScopes(StringUtils.str2List(oauth2Client.getScope(), null));
        }

        result.setAuthorizedGrantTypes(StringUtils.str2List(oauth2Client.getAuthorizedGrantTypes(), null));
        result.setAccessTokenValiditySeconds(oauth2Client.getAccessTokenValidity());
        result.setRefreshTokenValiditySeconds(oauth2Client.getRefreshTokenValidity());
        List<String> rus = StringUtils.str2List(oauth2Client.getRedirectUri(), null);
        result.setRegisteredRedirectUri(rus.stream().collect(Collectors.toSet()));

        if(oauth2Client.getAdditionalInformation() != null) {
            try {
                result.setAdditionalInformation(objectMapper.readValue(oauth2Client.getAdditionalInformation(), Map.class));
            } catch (JsonProcessingException e) {
                log.error("转化失败", e);
                throw new ClientRegistrationException("转化失败");
            }
        }

        return result;
    }

}
