package com.freshjuice.isomer.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CharacterEncodingFilter;

import javax.servlet.Filter;

@Configuration
public class FlServletConfig {

    /**
     * spring  CharacterEncodingFilter encoding
	 * @return
    */
    @Bean
    public FilterRegistrationBean<Filter> characterFilter() {
        FilterRegistrationBean<Filter> filterRegistrationBean = new FilterRegistrationBean<Filter>();
        CharacterEncodingFilter characterFilter = new CharacterEncodingFilter();
        characterFilter.setEncoding("UTF-8");
        characterFilter.setForceEncoding(true);
        filterRegistrationBean.setFilter(characterFilter);
        filterRegistrationBean.addUrlPatterns("/*");
        filterRegistrationBean.setOrder(1);
        return filterRegistrationBean;
    }

}
