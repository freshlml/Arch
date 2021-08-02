package com.freshjuice.auth;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.freshjuice.auth.security.clientdetails.DbClientDetailsService;
import com.freshjuice.auth.security.entity.Oauth2Client;
import com.freshjuice.auth.security.entity.User;
import com.freshjuice.auth.security.service.Oauth2ClientService;
import com.freshjuice.auth.security.service.UserService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;
import java.util.function.Supplier;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SecurityAuthUserTest {

    @Autowired
    private UserService userService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    //@Transactional
    @Test
    public void user() {

        User user1 = new User();
        user1.setUserName("di");
        user1.setPassword(bCryptPasswordEncoder.encode("ioc"));
        user1.setPhone("15623236821");
        userService.save(user1);

        User user2 = new User();
        user2.setUserName("dl");
        user2.setPassword(bCryptPasswordEncoder.encode("ioc"));
        user2.setPhone("13237177828");
        userService.save(user2);



    }

    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private Oauth2ClientService oauth2ClientService;
    private Supplier<String> secretGenerateStrategy = () -> UUID.randomUUID().toString();

    @Test
    public void oauth2Client() {

        oauth2ClientService.remove(new LambdaQueryWrapper<Oauth2Client>().in(Oauth2Client::getClientId, "for_own", "for_client_credentials", "for_other"));

        Oauth2Client clientOwn = new Oauth2Client();
        clientOwn.setClientId("for_own");
        clientOwn.setClientSecret(secretGenerateStrategy.get());
        clientOwn.setScope("all");
        clientOwn.setAuthorities(null);
        clientOwn.setResourceIds(null);
        clientOwn.setAutoApprove(0);
        clientOwn.setAuthorizedGrantTypes("password,phone_code,refresh_token");
        clientOwn.setAccessTokenValidity(43200);
        clientOwn.setRefreshTokenValidity(86400);
        clientOwn.setRedirectUri(null);
        clientOwn.setAdditionalInformation(null);
        oauth2ClientService.save(clientOwn);

        Oauth2Client clientCredentials = new Oauth2Client();
        clientCredentials.setClientId("for_client_credentials");
        clientCredentials.setClientSecret(secretGenerateStrategy.get());
        clientCredentials.setScope("oauth2_user_client");
        clientCredentials.setAuthorities(null);
        clientCredentials.setResourceIds(null);
        clientCredentials.setAutoApprove(0);
        clientCredentials.setAuthorizedGrantTypes("client_credentials");
        clientCredentials.setAccessTokenValidity(3600);
        clientCredentials.setRefreshTokenValidity(14400);
        clientCredentials.setRedirectUri(null);
        clientCredentials.setAdditionalInformation("{\"code\":\"code值\",\"value\":123456789}");
        oauth2ClientService.save(clientCredentials);



        Oauth2Client clientOther = new Oauth2Client();
        clientOther.setClientId("for_other");
        clientOther.setClientSecret(secretGenerateStrategy.get());
        clientOther.setScope("oauth2_user");
        clientOther.setAuthorities(null);
        clientOther.setResourceIds(null);
        clientOther.setAutoApprove(0);
        clientOther.setAuthorizedGrantTypes("authorization_code,implicit,refresh_token");
        clientOther.setAccessTokenValidity(43200);
        clientOther.setRefreshTokenValidity(86400);
        clientOther.setRedirectUri("http://localhost:7107/login/oauth2/test_other");
        clientOther.setAdditionalInformation(null);
        oauth2ClientService.save(clientOther);

    }

    @Test
    public void oauth2ClientGet() {
        ClientDetails own = clientDetailsService.loadClientByClientId("for_own");
        ClientDetails credentials = clientDetailsService.loadClientByClientId("for_client_credentials");
        ClientDetails other = clientDetailsService.loadClientByClientId("for_other");

        System.out.println(own);
        System.out.println(credentials);
        System.out.println(other);
    }


}
