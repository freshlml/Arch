package com.freshjuice.isomer.interceptor;

import com.baomidou.mybatisplus.core.toolkit.PluginUtils;
import org.apache.ibatis.executor.statement.StatementHandler;
import org.apache.ibatis.plugin.*;

import java.sql.Connection;
import java.util.Properties;

@Intercepts({@Signature(type = StatementHandler.class, method="prepare", args={Connection.class, Integer.class})})
public class FlInterceptor implements Interceptor {
    private Properties properties = new Properties();

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        //获取被代理的目标对象
        StatementHandler statementHandler = PluginUtils.realTarget(invocation.getTarget());
        //do something
        return invocation.proceed();
    }
    /**
     * @param target 被代理的目标对象: Executor，StatementHandler，ParameterHandler，ResultSetHandler
     * @return
     */
    @Override
    public Object plugin(Object target) {
        if(target instanceof StatementHandler) {
            return Plugin.wrap(target, this);
        }
        return target;
    }
    /**
     * plugin配置的property
     * <plugin interceptor="com.sc.ExamplePlugin">
     *     <property name="key" value="value"/>
     * </plugin>
     * @param properties
     */
    @Override
    public void setProperties(Properties properties) {
        properties.putAll(properties);
    }
}
