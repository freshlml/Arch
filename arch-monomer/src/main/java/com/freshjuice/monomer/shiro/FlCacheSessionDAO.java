package com.freshjuice.monomer.shiro;

import org.apache.shiro.cache.AbstractCacheManager;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.MapCache;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.CachingSessionDAO;

import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;

public class FlCacheSessionDAO extends CachingSessionDAO {
    public static final String FL_SHIRO_SESSION_REDIS_PREFIX = "shiro:session";
    public static final String FL_SHIRO_SESSION_REDIS_SEP = ":";

    public FlCacheSessionDAO() {
        this.setCacheManager(new AbstractCacheManager() {
            protected Cache<Serializable, Session> createCache(String name) throws CacheException {
                return new MapCache(name, new ConcurrentHashMap());
            }
        });
    }

    protected Serializable doCreate(Session session) {
        Serializable sessionId = this.generateSessionId(session);
        sessionId = FL_SHIRO_SESSION_REDIS_PREFIX + FL_SHIRO_SESSION_REDIS_SEP + sessionId;
        this.assignSessionId(session, sessionId);
        return sessionId;
    }

    protected Session doReadSession(Serializable sessionId) {
        return null;
    }

    protected void doUpdate(Session session) {
    }

    protected void doDelete(Session session) {
    }

}
