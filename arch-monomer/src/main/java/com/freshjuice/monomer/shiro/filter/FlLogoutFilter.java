package com.freshjuice.monomer.shiro.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.freshjuice.monomer.common.utils.FlWebUtils;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@Component("flLogoutFilter")
public class FlLogoutFilter extends LogoutFilter {
    private static final Logger log = LoggerFactory.getLogger(FlLogoutFilter.class);
    public FlLogoutFilter(String redirectUrl, boolean postOnlyLogout) {
        super();
        this.setRedirectUrl(redirectUrl);
        this.setPostOnlyLogout(postOnlyLogout);
    }
    public FlLogoutFilter(String redirectUrl) {
        this(redirectUrl, false);
    }
    public FlLogoutFilter() {
        this("/", false);
    }
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = this.getSubject(request, response);
        if (this.isPostOnlyLogout() && !WebUtils.toHttp(request).getMethod().toUpperCase(Locale.ENGLISH).equals("POST")) {
            return this.onLogoutRequestNotAPost(request, response);
        } else {
            String redirectUrl = this.getRedirectUrl(request, response, subject);

            try {
                subject.logout();
            } catch (SessionException var6) {
                log.debug("Encountered session exception during logout.  This can generally safely be ignored.", var6);
            }

            if(FlWebUtils.fJsonRequestAcceptExtend((HttpServletRequest) request)) {
                response.setCharacterEncoding("UTF-8");
                response.setContentType("application/json; charset=UTF-8");
                Map<String, String> map = new HashMap<String, String>();
                map.put("code", "200");
                map.put("message", "logout success");
                ObjectMapper objectMapper = new ObjectMapper();
                response.getWriter().write(objectMapper.writeValueAsString(map));
            } else {
                this.issueRedirect(request, response, redirectUrl);
            }

            return false;
        }
    }
}
