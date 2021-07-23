package com.freshjuice.monomer;

import org.springframework.context.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@ComponentScan(basePackages = "com.freshjuice.monomer",
excludeFilters = {
		@ComponentScan.Filter(type=FilterType.ANNOTATION, value={Controller.class})
})
@EnableAspectJAutoProxy(proxyTargetClass=true)  //enable @Aspectj
@EnableTransactionManagement(proxyTargetClass=true) //enable transaction 注解
//@EnableCaching(proxyTargetClass=true) //enable caching
@Import(value={ApplicationDao.class, ApplicationCache.class, ApplicationShiro.class})
public class ApplicationConfig {
	
	//https://hanqunfeng.iteye.com/blog/2113820 零配置参照博客
	
	/*创建bean时，指定@Profile,表示该bean的有效空间，通过spring.profiles.active激活对应的profile （ArchIsomer中配置了prod,dev的原理就是这）*/
    /*@Bean
    @Profile("dev")
    public DataSource devDataSource() {
        return null;
    }
    @Bean
    @Profile("prod")
    public DataSource prodDataSource() {
        return null;
    }*/
    /*
    * spring.profiles.active
    * 1.作为DispatcherServlet的参数设置
    * 2.作为web应用的上下文参数设置
    * 3.JVM系统属性设置
    * 4.在集成测试类上使用@ActiveProfiles注解设置
    * 5.使用环境变量设置
    */

    /*条件化bean @Conditional*/

    /*bean的歧义性 @Primary @Qualifier*/

}
