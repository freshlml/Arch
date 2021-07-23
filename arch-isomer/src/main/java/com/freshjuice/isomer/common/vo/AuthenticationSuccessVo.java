package com.freshjuice.isomer.common.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors(chain = true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationSuccessVo {
    private String principal;
    private String credentials;
    private List<String> permissions;
    private String csrfToken;
    private String loginToken;
}
