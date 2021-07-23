package com.freshjuice.isomer.security.form;

import com.freshjuice.isomer.common.vo.AuthenticationSuccessVo;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

public class CompositeAuthenticationSuccessVoResolver implements AuthenticationSuccessVoResolver {

    private List<AuthenticationSuccessVoResolver> providers = new ArrayList<>();

    public CompositeAuthenticationSuccessVoResolver() {
        providers.add(new UsernamePasswordAuthenticationTokenSuccessVoResolver());

        //providers.add(new DefaultAuthenticationSuccessVoResolver());  //the last
    }

    @Override
    public boolean supports(Class<?> type) {
        return true;
    }

    @Override
    public AuthenticationSuccessVo createVo(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        AuthenticationSuccessVo result = null;
        for(AuthenticationSuccessVoResolver provider : providers) {
            if(provider.supports(authentication.getClass())) {
                try {
                    result = provider.createVo(authentication, request, response);
                    if(result != null) {
                        break;
                    }
                } catch (Exception e) {
                    continue;
                }
            }
        }
        if(result == null) {
            result = new DefaultAuthenticationSuccessVoResolver().createVo(authentication, request, response);
        }
        return result;
    }
}
