package com.freshjuice.auth.security.entity;

import com.freshjuice.auth.common.entity.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Oauth2Client extends BaseEntity<Long> {

    private String clientId;
    private String clientSecret;

    private String scope;
    private String authorities;
    private String resourceIds;
    private Integer autoApprove;   //tinyint

    private String authorizedGrantTypes;
    private Integer accessTokenValidity;
    private Integer refreshTokenValidity;
    private String redirectUri;
    private String additionalInformation;



}
