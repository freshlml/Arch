package com.freshjuice.monomer.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.List;

/**
 * 重定义多个realm存在时的成功strategy
 * 1 保持基类AtLeastOneSuccessfulStrategy原有strategy不变：至少有一个realm成功
 * 2 重写其异常抛出代码：将realm中的异常抛出
 */
public class FlMultiRealmSuccessfulStrategy extends AtLeastOneSuccessfulStrategy {

    private List<AuthenticationException> realmExceptions = new ArrayList<AuthenticationException>();

    @Override
    public AuthenticationInfo afterAllAttempts(AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        if (aggregate != null && !isEmpty(aggregate.getPrincipals())) {
            return aggregate;
        } else {
            if(realmExceptions.get(0) != null) {AuthenticationException t=realmExceptions.get(0);realmExceptions = null;realmExceptions = new ArrayList<AuthenticationException>();throw t;}
            else throw new AuthenticationException("Authentication token of type [" + token.getClass() + "] " + "could not be authenticated by any configured realms.  Please ensure that at least one realm can " + "authenticate these tokens.");
        }

    }

    @Override
    public AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo singleRealmInfo, AuthenticationInfo aggregateInfo, Throwable t) throws AuthenticationException {
        AuthenticationInfo info;
        if (singleRealmInfo == null) {
            info = aggregateInfo;
        } else if (aggregateInfo == null) {
            info = singleRealmInfo;
        } else {
            info = this.merge(singleRealmInfo, aggregateInfo);
        }
        if(t != null) {
            if(t instanceof AuthenticationException)
                realmExceptions.add((AuthenticationException) t);
            else realmExceptions.add(new AuthenticationException(t));
        }
        return info;
    }

    private static boolean isEmpty(PrincipalCollection pc) {
        return pc == null || pc.isEmpty();
    }
}
