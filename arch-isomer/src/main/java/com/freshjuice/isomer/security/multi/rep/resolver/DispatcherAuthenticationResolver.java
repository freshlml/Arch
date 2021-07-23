package com.freshjuice.isomer.security.multi.rep.resolver;

import com.freshjuice.isomer.security.multi.rep.LoginParam;
import com.freshjuice.isomer.security.multi.rep.exception.LoginParamNotNullException;
import com.freshjuice.isomer.security.multi.rep.token.LoginParamAuthenticationToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.ArrayList;
import java.util.List;

public class DispatcherAuthenticationResolver implements AuthenticationResolver {
    private List<AbstractAuthenticationResolver> resolvers = new ArrayList<>();

    public DispatcherAuthenticationResolver() {
        addResolver(new PasswordAuthenticationResolver());
        addResolver(new DefaultAuthenticationResolver());
    }

    public void addResolver(AbstractAuthenticationResolver resolver) {
        resolvers.add(resolver);
    }

    @Override
    public AbstractAuthenticationToken resolve(LoginParam loginParam) {
        AbstractAuthenticationResolver resolverToUse = resolvers.stream().filter(resolver -> resolver.supports(loginParam)).findFirst().orElse(new DefaultAuthenticationResolver());
        return resolverToUse.resolve(loginParam);
    }

    private static class DefaultAuthenticationResolver extends AbstractAuthenticationResolver {

        @Override
        public boolean supports(LoginParam loginParam) {
            return true;
        }

        @Override
        public String supportsTag() {
            return "DEFAULT";
        }

        @Override
        public AbstractAuthenticationToken resolve(LoginParam loginParam) {
            if(loginParam == null) throw new LoginParamNotNullException("登录参数不能为空,loginParam=null");
            if(loginParam.getType() == null) throw new LoginParamNotNullException("登录参数不能为空,loginParam.type=null");
            LoginParamAuthenticationToken token = new LoginParamAuthenticationToken(loginParam);
            return token;
        }
    }

}
