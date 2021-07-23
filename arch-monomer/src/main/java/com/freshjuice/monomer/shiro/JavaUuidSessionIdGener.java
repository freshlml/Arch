package com.freshjuice.monomer.shiro;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;

import java.io.Serializable;
import java.util.UUID;

public class JavaUuidSessionIdGener implements SessionIdGenerator {
    public JavaUuidSessionIdGener() {
    }

    public Serializable generateId(Session session) {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }
}
