package com.freshjuice.monomer;

import com.freshjuice.monomer.common.exception.FlRootExceptionResolver;
import com.freshjuice.monomer.interceptor.FlHandlerInterceptor;
import com.freshjuice.monomer.priority.service.ResourcePriorityService;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.util.PathMatcher;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;
import org.springframework.web.util.UrlPathHelper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@ComponentScan(basePackages = "com.freshjuice.monomer",
	includeFilters = {
			@ComponentScan.Filter(type=FilterType.ANNOTATION, value={Controller.class})
})
public class ApplicationMvcConfig extends WebMvcConfigurationSupport {
	/**
	 * 继承WebMvcConfigurationSupport,提供了默认的配置,一般实现相关接口方法实现具体逻辑
	 * 
	 */
	
	/**
	 * for handlerAdapter add  messageConverters
	 */
	@Bean
	public MappingJackson2HttpMessageConverter jacksonConverter() {
		MappingJackson2HttpMessageConverter jacksonConverter = new MappingJackson2HttpMessageConverter();
		List<MediaType> supportedMediaTypes = new ArrayList<MediaType>();
		supportedMediaTypes.add(MediaType.APPLICATION_JSON_UTF8);
		jacksonConverter.setSupportedMediaTypes(supportedMediaTypes);
		return jacksonConverter;
	}
	protected void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
		converters.add(jacksonConverter());
	}

	@Autowired
	private ResourcePriorityService resourcePriorityService;

	@Bean
	public FlHandlerInterceptor flBaseInterceptor() {
		FlHandlerInterceptor flBaseInterceptor = new FlHandlerInterceptor();
		flBaseInterceptor.setResourceService(resourcePriorityService);
		return flBaseInterceptor;
	}

	@Override
	@Bean
	public RequestMappingHandlerMapping requestMappingHandlerMapping() {
		RequestMappingHandlerMapping handlerMapping = createRequestMappingHandlerMapping();
		handlerMapping.setOrder(0);
		List<Object> interceptorList = new ArrayList<Object>();
		interceptorList.addAll(Arrays.asList(getInterceptors()));
		interceptorList.add(flBaseInterceptor());           //只为此mapping添加interceptor
		handlerMapping.setInterceptors(interceptorList.toArray());
		handlerMapping.setContentNegotiationManager(mvcContentNegotiationManager());
		handlerMapping.setCorsConfigurations(getCorsConfigurations());

		PathMatchConfigurer configurer = getPathMatchConfigurer();
		if (configurer.isUseSuffixPatternMatch() != null) {
			handlerMapping.setUseSuffixPatternMatch(configurer.isUseSuffixPatternMatch());
		}
		if (configurer.isUseRegisteredSuffixPatternMatch() != null) {
			handlerMapping.setUseRegisteredSuffixPatternMatch(configurer.isUseRegisteredSuffixPatternMatch());
		}
		if (configurer.isUseTrailingSlashMatch() != null) {
			handlerMapping.setUseTrailingSlashMatch(configurer.isUseTrailingSlashMatch());
		}
		UrlPathHelper pathHelper = configurer.getUrlPathHelper();
		if (pathHelper != null) {
			handlerMapping.setUrlPathHelper(pathHelper);
		}
		PathMatcher pathMatcher = configurer.getPathMatcher();
		if (pathMatcher != null) {
			handlerMapping.setPathMatcher(pathMatcher);
		}

		return handlerMapping;
	}

	/**
	 * 配置一个mapping(order=Int.MAX_VALUE-1)，该Mapping使用自定义的规则对请求进行mapping
	 * 如registry.addResourceHandler("/css/**").addResourceLocations("/css/"); 
	 * 当order<Int.MAX_VALUE-1的mapping处理不了时，此处mapping将/css/a.css请求去/css/目录下加载
	 * 
	 * 如registry.addResourceHandler("/statics/**").addResourceLocations("/WEB-INF/statics/");
	 * 能够加载WEB-INF目录下面资源
	 * 
	 * 如registry.addResourceHandler("/statics/**").addResourceLocations("classpath:/statics/");
	 * 实际加载的是WEB-INF/classes目录下面的资源
	 * 
	 * 与@EnableWebMvc的冲突
	 */
	@Override
	protected void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/statics/**").addResourceLocations("classpath:/statics/", "/statics/");
	}
	/**
	 * 配置一个mapping(order=Int.MAX_VALUE)，该Mapping使用servlet容器的 default servlet
	 * 一般而言，当DispatcherServlet拦截/时，对于/js/1.js请求      RequestMappingHandlerMapping没有对应的mapping
	 * 这时将会使用 此处配置的 Mapping使用default servlet加载 /js/1.js （注意，该defualt servlet不能加载/WEB-INF目录下资源）
	 * [当然，该Mapping的order=Int.MAX_VALUE，这就需要该请求在order<Int.MAX_VALUE没有被处理，才能执行到此处]
	 * 与@EnableWebMvc注解的冲突？
	 * 
	 * 2019-4-23更新，禁用该mapping，FlWebInitializer中说明了原因
	 */
	/*@Override
	protected void configureDefaultServletHandling(
			DefaultServletHandlerConfigurer configurer) {
		configurer.enable();
	}*/
	
	/**
	 * viewResolver
	 * spring标签库
	 * jstl标签库
	 */
	@Bean
	public ViewResolver viewResolver() {
		InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
		viewResolver.setViewClass(JstlView.class);
		viewResolver.setPrefix("/");
		viewResolver.setSuffix(".jsp");
		return viewResolver;
	}
	/**
	 * thymeleaf 视图 配置 start
	 */
	/*@Bean
	public ViewResolver thymeleafViewResolver(SpringTemplateEngine templateEngine) {
		ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
		viewResolver.setTemplateEngine(templateEngine);
		return viewResolver;
	}
	@Bean
	public TemplateEngine templateEngine(ITemplateResolver templateResolver) {
		SpringTemplateEngine templateEngine = new SpringTemplateEngine();
		templateEngine.setTemplateResolver(templateResolver);
		return templateEngine;
	}
	@Bean
	public ITemplateResolver templateResolver() {
		//SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
		ServletContextTemplateResolver templateResolver = new ServletContextTemplateResolver(ContextLoader.getCurrentWebApplicationContext().getServletContext());
	    templateResolver.setPrefix("classpath:/thymeleaf/");
	    templateResolver.setCacheable(false);
	    templateResolver.setCharacterEncoding("UTF-8");
	    templateResolver.setSuffix(".html");
	    templateResolver.setTemplateMode("HTML5");
	    return templateResolver;
	}*/
	/**
	 * thymeleaf 视图配置 end
	 */
	
	/**
	 * multipartResolver
	 * 使用StandardServletMultipartResolver
	 * multipartResolver注册到 DispatcherServlet，其中文件上传的配置在DispatcherServlet中multipart-config
	 */
	@Bean
	public MultipartResolver multipartResolver() {
		return new StandardServletMultipartResolver();
	}
	
	/**
	 * Locale
	 * SessionLocalResolver
	 * LocalChangeIntercepter
	 */
	@Bean
	public LocaleResolver localResolver() {
		return new SessionLocaleResolver();
	}
	@Bean
	public LocaleChangeInterceptor localChangeInterceptor() {
		LocaleChangeInterceptor localChangeInterceptor = new LocaleChangeInterceptor();
		return localChangeInterceptor;
	}
	@Override
	protected void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(localChangeInterceptor());
	}
	
	/**
	 * exception resolver  分析与实践
	 * 
	 * DispatcherServlet中定义了chain形式ExceptionResolvers,按chain执行（根据order排序）
	 * 默认添加的ExceptionResolver: 
	 * [0] ExceptionHandlerExceptionResolver 处理Controller中@ExceptionHanlder 或者@ControllerAdvice中@ExceptionHanlder
	 * {1、定义一个Interceptor,判断HandlerMapping上是否有ResponseBody注解，从而判断是返回JSON还是VIEW
	 * 	2、在@ExceptionHandler定义的方法中就可以判断是返回JSON还是VIEW
	 * 如ModelAndView mv = new ModelAndView(new MappingJackson2JsonView());mv.addObject("code", "500"); 将返回JSON
	 * } {
	 * 	在@ExeceptionHandler定义的方法中通过request.getHeader("Accept");判断如果text/html，则返回view否则返回json
	 * }
	 * 
	 * [1] ResponseStatusExceptionResolver 处理@ResponseStatus的异常
	 * 将状态码和reason返回，返回的view格式
	 * 
	 * [2] DefaultHandlerExceptionResolver
	 * 默认处理特定的一些异常
	 * 
	 * 
	 * 
	 * 问题1：一般不好判定，发生异常之后收返回error页面还是json错误提示
	 * 1)、@ControllerAdvice@ExceptionHandler模式下通过 Interceptor判断
	 * 2)、@ControllerAdvice@ExceptionHandler模式下通过request中Accept判断
	 * 
	 * 问题2 spring mvc中异常位置如下， 如何将所有的异常都处理
	 * 1、进入@Controller之前，如url地址错误，导致无法匹配mapping
	 * 1)、默认将会被DefaultHandlerExceptionResolver
	 * 
	 * 2、执行@Controller中业务逻辑代码之前，如参数解析器解析错误
	 * 1)、执行到HandlerAdapter，通过@ControllerAdvice@ExceptionHandler模式处理
	 * 
	 * 3、执行Controller业务方法发生异常
	 * 1)、业务方法执行的异常，通过@ControllerAdvice@ExceptionHandler模式处理
	 * 
	 * 4、执行完Controller业务方法之后对result和ModelAndView的异常
	 * 1）、viewName写错： 由视图解析器解析时调用DispatcehrServlet的forward操作（在DispatcherServlet执行完之后，真正写给client时抛异常给servlet容器）
	 * 
	 * 
	 * 目前的解决方案：
	 * [0] ExceptionHandlerExceptionResolver
	 * [1] ResponseStatusExceptionResolver
	 * [2] 自定义类似sb的ExceptionResolver，将异常转发到ErrorController中
	 * 
	 * 或者直接实现HandlerExceptionResolver接口  作为 唯一的一个 异常处理器
	 * ModelAndView resolveException(
			HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex);
	 * 
	 * [FlRootExceptionResolver]
	 */
	@Bean
	public FlRootExceptionResolver flRootExceptionResolver() {
		return new FlRootExceptionResolver();
	}
	@Override
	protected void configureHandlerExceptionResolvers(
			List<HandlerExceptionResolver> exceptionResolvers) {
		addDefaultHandlerExceptionResolvers(exceptionResolvers);  
		exceptionResolvers.add(2, flRootExceptionResolver());  //添加到 DefaultHandlerExceptionResolver 之前
	}
	/**
	 * 关于no handlerfound exception的处理源码
	 * protected void noHandlerFound(HttpServletRequest request, HttpServletResponse response) throws Exception {
		if (pageNotFoundLogger.isWarnEnabled()) {
			pageNotFoundLogger.warn("No mapping found for HTTP request with URI [" + getRequestUri(request) +
					"] in DispatcherServlet with name '" + getServletName() + "'");
		}
		if (this.throwExceptionIfNoHandlerFound) {
			throw new NoHandlerFoundException(request.getMethod(), getRequestUri(request),
					new ServletServerHttpRequest(request).getHeaders());
		}
		else {
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
		}
	}
	 * 即，默认情况下，response.sendError(HttpServletResponse.SC_NOT_FOUND); 这将写404给servlet容器，servelt容器处理该404（在web.xml中配置404的返回页面）
	 * 所以，可以通过设置throwExceptionIfNoHandlerFound=true，让该异常执行spring mvc中的异常逻辑
	 * 
	 */
	
	
	
	/**
	 * 如果配置多个handler mapping order，如WebMvcConfigurationSupport中定义了很多中handler mapping  order值不同
	 * DispatcherServlet配置路径 / 则所有的请求都会走DispatcherServlet，mapping时将按照order顺序
	 */
	
	
	/**
	 * 视图解析器应当给予更多的实际应用与操作
	 */
	
	/*Authority advisor*/
	@Bean
	public AuthorizationAttributeSourceAdvisor
			authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
		AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = 
				new AuthorizationAttributeSourceAdvisor();
		authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
		return authorizationAttributeSourceAdvisor;
	}
	@Bean("lifecycleBeanPostProcessor")
    public static LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }
	@Bean
	@DependsOn("lifecycleBeanPostProcessor")
	public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
		DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
		defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);
		return defaultAdvisorAutoProxyCreator;
	}
	
}
