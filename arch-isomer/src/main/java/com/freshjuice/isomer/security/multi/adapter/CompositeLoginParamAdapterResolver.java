package com.freshjuice.isomer.security.multi.adapter;

import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;
import java.util.List;

public class CompositeLoginParamAdapterResolver implements LoginParamAdapterResolver {
    private final List<AbstractLoginParamAdapterResolver> resolvers = new ArrayList<>();
    private final DefaultLoginParamResolver defaultLoginParamResolver = new DefaultLoginParamResolver(null);

    @Override
    public LoginParamAdapter resolve(LoginParamAdapter loginParam) {
        AbstractLoginParamAdapterResolver resolverToUse = resolvers.stream().filter(resolver -> resolver.supports(loginParam)).findFirst().orElse(defaultLoginParamResolver);
        return resolverToUse.resolve(loginParam);
    }

    public void addResolver(AbstractLoginParamAdapterResolver resolver) {
        resolvers.add(resolver);
    }

    private static class DefaultLoginParamResolver extends AbstractLoginParamAdapterResolver {

        public DefaultLoginParamResolver(LoginParamAdapterService loginParamService) {
            super(loginParamService);
        }

        public boolean supports(LoginParamAdapter loginParam) {
            return true;
        }

        @Override
        protected String getSupportsTag() {
            return "";
        }

        @Override
        public LoginParamAdapter resolve(LoginParamAdapter loginParam) throws AuthenticationException {
            throw new LoginParamAdapterAuthenticationException("登录失败");
        }
    }
}
