package com.freshjuice.monomer;

import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletRegistration.Dynamic;

public class FlWebInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {
	
	/**
	 * spring listener 上下文配置
	 */
	@Override
	protected Class<?>[] getRootConfigClasses() {
		return new Class[]{ApplicationConfig.class, ApplicationTextConfig.class};
	}
	
	/**
	 * dispacher servlet 上下文配置
	 */
	@Override
	protected Class<?>[] getServletConfigClasses() {
		return new Class[]{ApplicationMvcConfig.class};
	}

	/**
	 * dispacher servlet 映射
	 * 配置成 / ，  将拦截所有请求如   /test /1.js /2.css ,（除了  jsp后缀的 不能拦截之外）
	 * 
	 * 而这将覆盖servlet容器中配置的  拦截/ 的 defaultServlet （该servlet根据请求路径获得文件，通过response写，如 /1.js， 会定位到1.js的真实路径，response写）
	 * 
	 * 注意： /ArchMonomer/ 这种形式的url，先根据welcome-file配置找寻文件
	 * 这里通过
	 * <welcome-file-list>
	 *		<welcome-file></welcome-file>
	 * </welcome-file-list>
	 * 禁用默认的welcome-file，则应该在controller中配置一个@RequestMapping("/")
	 * 
	 * important: 
	 * 1、这里应该禁用掉使用default servlet的mapping
	 * 2、使用mapping(order=Int.MAX_VALUE-1)加载静态资源
	 * 
	 * 而，we all kown,spring boot default setServletMappings to /*
	 * 1、/*的优先级高于/，不会覆盖default servlet /，而所有请求都会被/*拦截
	 * 2、/*拦截所有的请求，包括.jsp请求
	 * 3、spring boot 中显然没有开启 使用defaultServlet对应的mapping
	 * @Override
	protected void configureDefaultServletHandling(
			DefaultServletHandlerConfigurer configurer) {
		configurer.enable();
	}
	 * 因为一旦开启，意味着，
	 * a:如果一个404请求如/fjdkasf，能够找到mapping,该mapping找不到该文件，写给servlet容器404，则显示的是默认的404页面不友好
	 *   而DispatcherServlet中对于no handler found的处理是，如果找不到对应的mapping(404)，则可以将异常交给spring mvc的exception resolver处理
	 *   则对比a中描述的过程:[一个404请求,能够找到对应的mapping]就不会产生no handler found的异常
	 * b:如果一个404请求为静态资源如1.js，该mapping找不到该文件，写给servlet容器404，这是正常的逻辑
	 * 
	 * 4、spring boot 中会注册一个mapping(order=Int.MAX_VALUE-1),去处理配置的静态资源目录下面的资源的加载
	 * 
	 */
	@Override
	protected String[] getServletMappings() {
		return new String[]{"/"};
	}
	
	/**
	 * 
	 */
	@Override
	protected void customizeRegistration(Dynamic registration) {
		//配置StandardServletMultipartResolver的参数
		registration.setMultipartConfig(new MultipartConfigElement("/tmp/", 2097152, 4194304, 0));
		//设置DispatcherServlet的init-param
		registration.setInitParameter("throwExceptionIfNoHandlerFound", "true");  //当no handler异常时，抛给spring mvc的Exception resolver处理
	}
	
}
