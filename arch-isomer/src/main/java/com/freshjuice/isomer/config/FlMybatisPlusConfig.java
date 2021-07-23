package com.freshjuice.isomer.config;

import com.baomidou.mybatisplus.extension.plugins.PaginationInterceptor;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@MapperScan("com.freshjuice.isomer.**.mapper")
public class FlMybatisPlusConfig {

    /**
     * 分页插件启用
     */
    @Bean
    public PaginationInterceptor paginationInterceptor() {
        PaginationInterceptor paginationInterceptor = new PaginationInterceptor();
        // paginationInterceptor.setLimit(你的最大单页限制数量，默认 500 条，小于 0 如 -1 不受限制);
        return paginationInterceptor;
    }

    /**
     * mybatis-plus SQL执行效率插件【生产环境需要关闭，否则影响系统性能】
     */
    /*@Profile({"dev", "test"})
    @Bean
    public SqlExplainInterceptor performanceInterceptor() {
        return new SqlExplainInterceptor();
    }*/
}
