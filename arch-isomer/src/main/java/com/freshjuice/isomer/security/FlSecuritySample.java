package com.freshjuice.isomer.security;

public class FlSecuritySample {

    /**
     * spring security的使用取舍
     * 1、针对基于浏览器访问的spring security架子可以采用:{@link FlSecurityMultiSample},{@link FlSecurityFormSample}
     * 2、针对移动应用的无状态认证,基于浏览器访问的认证也可以采用无状态认证
     *    1)、JWT @see xy-common
     *    2)、OAuth2 @see ArchPoner
     */

    /**
     *依赖
     * spring-boot-starter-security
     *  spring-security-web
     *    spring-security-core
     *  spring-security-config
     *    spring-security-core
     */

    /**
     *第一:  FilterChainProxy,HttpFirewall,SecurityFilterChain
     *
     * FilterChainProxy{  HttpFirewall;使用RequestMatcher选择SecurityFilterChain
     *      SecurityFilterChain(0) {  Security拦截器链，SecurityFilter的顺序很重要
     *          ChannelProcessingFilter                     extends GenericFilterBean implements Filter
     *          WebAsyncManagerIntegrationFilter            extends OncePerRequestFilter extends GenericFilterBean
     *          SecurityContextPersistenceFilter            extends GenericFilterBean
     *          HeaderWriterFilter                          extends OncePerRequestFilter
     *          CorsFilter                                  extends GenericFilter implements Filter
     *          CsrfFilter                                  extends OncePerRequestFilter
     *          LogoutFilter                                extends GenericFilterBean
     *          OAuth2AuthorizationRequestRedirectFilter    spring-boot-starter-security中没有
     *          Saml2WebSsoAuthenticationRequestFilter      spring-boot-starter-security中没有
     *          X509AuthenticationFilter                    extends AbstractPreAuthenticatedProcessingFilter
     *          AbstractPreAuthenticatedProcessingFilter    此类的其他实现类
     *          CasAuthenticationFilter                     spring-boot-starter-security中没有
     *          OAuth2LoginAuthenticationFilter             spring-boot-starter-security中没有
     *          Saml2WebSsoAuthenticationFilter             spring-boot-starter-security中没有
     *          UsernamePasswordAuthenticationFilter        extends AbstractAuthenticationProcessingFilter
     *          OpenIDAuthenticationFilter                  spring-boot-starter-security中没有
     *          DefaultLoginPageGeneratingFilter            extends GenericFilterBean
     *          DefaultLogoutPageGeneratingFilter           extends OncePerRequestFilter
     *          ConcurrentSessionFilter                     extends GenericFilterBean
     *          DigestAuthenticationFilter                  extends GenericFilterBean
     *          BearerTokenAuthenticationFilter             spring-boot-starter-security中没有
     *          BasicAuthenticationFilter                   extends OncePerRequestFilter
     *          RequestCacheAwareFilter                     extends GenericFilterBean
     *          SecurityContextHolderAwareRequestFilter     extends GenericFilterBean
     *          JaasApiIntegrationFilter                    extends GenericFilterBean
     *          RememberMeAuthenticationFilter              extends GenericFilterBean
     *          AnonymousAuthenticationFilter               extends GenericFilterBean
     *          OAuth2AuthorizationCodeGrantFilter          spring-boot-starter-security中没有
     *          SessionManagementFilter                     extends GenericFilterBean
     *          ExceptionTranslationFilter                  extends GenericFilterBean
     *          FilterSecurityInterceptor                   implements Filter
     *          SwitchUserFilter                            extends GenericFilterBean
     *      }
     *      ...
     *      SecurityFilterChain(n) {
     *          SecurityFilter(0)
     *          ...
     *          SecurityFilter(n)
     *      }
     * }
     *
     *HttpFirewall{
     *  FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException;
     *  HttpServletResponse getFirewalledResponse(HttpServletResponse response);
     *}
     *HttpFirewall在FilterChainProxy中执行，如果抛出RequestRejectedException，异常会转发到/error
     *FlBasicErrorController mapping到 /error地址
     *
     *
     *第二: SecurityContextHolder,SecurityContext,Authentication
     *
     * SecurityContextHolder{  在当前线程中保存SecurityContext
     *     SecurityContext{    保存用户的认证信息Authentication
     *         Authentication{  封装用户的认证信息
     *             Object principal                                     用户标识,eg: username,phone,email
     *             Object credentials                                   用户凭据,eg: password,token,certificate
     *             Collection<? extends GrantedAuthority> authorities   用户资源权限,也可以是roles，看怎么定义
     *         }
     *         UsernamePasswordAuthenticationToken {
     *              Collection<GrantedAuthority> authorities; //在UserDetailsService加载
     *              Object details;       //额外信息
     *              boolean authenticated;
     *              Object principal;     //UserDetails类型,通过UserDetailsService加载
     *              Object credentials;   //String类型，存储密码
     *         }
     *         RememberMeAuthenticationToken {
     *              Collection<GrantedAuthority> authorities;
     *              Object details;
     * 	            boolean authenticated;
     *              Object principal;
     *              int keyHash;
     *         }
     *         PreAuthenticatedAuthenticationToken {
     *              Collection<GrantedAuthority> authorities;
     *              Object details;
     *              boolean authenticated;
     *              Object principal;
     *              Object credentials;
     *         }
     *     }
     * }
     *
     *SecurityContextPersistenceFilter，此filter在SecurityFilterChain的顺序@see FilterChainProxy/SecurityFilterChain(0)
     * public class SecurityContextPersistenceFilter {
     *      //TODO,1、SecurityContextRepository,保存/读取SecurityContext，默认基于Session的实现是HttpSessionSecurityContextRepository:将SecurityContext保存在HttpSession
     *      private SecurityContextRepository repo;
     *      public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
     * 			        throws IOException, ServletException {
     * 		        HttpServletRequest request = (HttpServletRequest) req;
     * 		        HttpServletResponse response = (HttpServletResponse) res;
     * 		        if (request.getAttribute(FILTER_APPLIED) != null) {
     * 			        chain.doFilter(request, response);
     * 			        return;
     *              }
     * 		        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
     *
     * 		        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
     * 	            //TODO,2、从SecurityContextRepository读取SecurityContext
     * 		        SecurityContext contextBeforeChainExecution = repo.loadContext(holder);
     * 		        try {
     * 	                //TODO,3、在当前线程中保存SecurityContext
     * 			        SecurityContextHolder.setContext(contextBeforeChainExecution);
     * 			        chain.doFilter(holder.getRequest(), holder.getResponse());
     *              } finally {
     * 			        SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
     * 		            //TODO,4、Filter链执行之后，当前线程清空SecurityContext
     * 			        SecurityContextHolder.clearContext();
     * 		            //TODO,5、将SecurityContext(从当前线程读取的)保存到SecurityContextRepository
     * 			        repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
     * 			        request.removeAttribute(FILTER_APPLIED);
     *              }
     *      }
     * }
     *
     *SecurityContextRepository {
     *    //如果没有SecurityContext，不会返回null，而是创建一个空SecurityContext
     *    SecurityContext loadContext(HttpRequestResponseHolder);
     *    //保存SecurityContext
     *    void saveContext(SecurityContext context, HttpServletRequest request,HttpServletResponse response);
     *    //SecurityContext是否存在
     *    boolean containsContext(HttpServletRequest);
     *}
     *HttpSessionSecurityContextRepository {  基于HttpSession的实现
     *  //将SecurityContext保存在HttpSession
     *  //TODO,很显然这里的HttpSession实现可以是servlet的HttpSession也可以是spring session wrap的实现，但不论哪种实现，对于调用者来说都是无感的
     *  HttpSession httpSession = request.getSession(false);
     *  httpSession.setAttribute(springSecurityContextKey, context);
     *}
     *
     *
     *第三.1: HeaderWriterFilter
     * 写给前端的header信息
     *HeaderWriterFilter {
     *      final List<HeaderWriter> headerWriters;
     *
     *      protected void doFilterInternal(HttpServletRequest request,
     * 			HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
     *
     * 		    HeaderWriterResponse headerWriterResponse = new HeaderWriterResponse(request, response, this.headerWriters);
     * 		    HeaderWriterRequest headerWriterRequest = new HeaderWriterRequest(request, headerWriterResponse);
     * 		    try {
     * 			    filterChain.doFilter(headerWriterRequest, headerWriterResponse);
     *          } finally {
     *              //TODO,如果chain中Response已经commit，则chain中commit处将会触发headerWriterResponse.onResponseCommitted()
     *              //TODO,如果chain中Response没有commit，则headerWriterResponse.disableOnCommitted=false
     * 			    headerWriterResponse.writeHeaders();
     *          }
     *      }
     *
     *      //TODO,Response中写header,然后将disableOnCommitted=true
     *      protected void onResponseCommitted() {
     * 			writeHeaders();
     * 			this.disableOnResponseCommitted();
     *      }
     *      //TODO,如果disableOnCommitted=false，Response中写header
     *      protected void writeHeaders() {
     * 			if (isDisableOnResponseCommitted()) {
     * 				return;
     *          }
     * 			for (HeaderWriter headerWriter : this.headerWriters) {
     * 				headerWriter.writeHeaders(this.request, getHttpResponse());
     *          }
     *      }
     *}
     *HeaderWriter{
     *     void writeHeaders(HttpServletRequest request, HttpServletResponse response);
     *}
     *
     *HeaderWriter实现类与配置
     *默认配置下
     *HeaderWriterFilter中的headerWriters
     *    XContentTypeOptionsHeaderWriter
     *    XXssProtectionHeaderWriter
     *    CacheControlHeadersWriter
     *    HstsHeaderWriter
     *    XFrameOptionsHeaderWriter
     *
     *so many headers
     *
     *
     *
     *第三.2: cors
     * cors()配置将在chain中写入CorsFilter
     *1、提供CorsConfigurationSource实现
     *2、否则使用spring mvc中配置的跨域
     *跨域请求与响应:
     * 1、发起请求时，请求头中带Origin(不带Origin头，服务器不进行跨域判断)
     * 2、根据cors配置判断是否允许跨域访问
     * 3、如果允许跨域访问，在response中添加origin相关的头，并转发请求
     *
     *
     *第四: Csrf
     *Csrf: Cross Site Request Forgery(跨站请求伪造)
     *
     *CsrfToken {
     *  String getHeaderName();
     * 	String getParameterName();
     *  String getToken();
     *}
     *CsrfTokenRepository {
     *  CsrfToken generateToken(HttpServletRequest request);
     *  void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response);
     *  CsrfToken loadToken(HttpServletRequest request);
     *}实现类有HttpSessionCsrfTokenRepository，Cooke
     *HttpSessionCsrfTokenRepository {
     *  String parameterName = "_csrf";
     * 	private String headerName = "X-CSRF-TOKEN";
     * 	private String sessionAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");
     *
     *  generateToken: new DefaultCsrfToken(this.headerName, this.parameterName, UUID)
     *  saveToken: 在HttpSession的Attr中保存: <sessionAttributeName-token>
     *  loadToken: 在HttpSession中加载token
     *}CookieCsrfTokenRepository {
     *  String parameterName = "_csrf";
     * 	String headerName = "X-XSRF-TOKEN";
     * 	String cookieName = "XSRF-TOKEN";
     *
     *  generateToken: new DefaultCsrfToken(this.headerName, this.parameterName, UUID)
     *  saveToken: 写到Cookie中，Cookie写到Response，这样客户端可以读取到此token
     *  loadToken: 从Cookie中加载token
     *}
     *
     *CsrfFilter {
     *      CsrfTokenRepository tokenRepository;
     *      //TODO,exceptionHandling().accessDeniedHandler配置的值写到了这里,csrf()本生不能配置
     *      AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
     *      RequestMatcher requireCsrfProtectionMatcher = new DefaultRequiresCsrfMatcher();
     *
     *      protected void doFilterInternal(HttpServletRequest request,
     * 			HttpServletResponse response, FilterChain filterChain)
     * 					throws ServletException, IOException {
     *
     * 		    request.setAttribute(HttpServletResponse.class.getName(), response);
     * 		    CsrfToken csrfToken = this.tokenRepository.loadToken(request);
     * 		    final boolean missingToken = csrfToken == null;  //TODO,csrfToken丢失或者是第一个请求token还未生成
     * 		    if (missingToken) {//TODO,重新生成或者第一个请求到来时生成Token,并且保存此token
     * 			    csrfToken = this.tokenRepository.generateToken(request);
     * 			    this.tokenRepository.saveToken(csrfToken, request, response);
     *          }
     *
     *          //TODO,在request中保存Token，这是为了让jsp等页面能够获取token的值(前后端不分离)
     * 		    request.setAttribute(CsrfToken.class.getName(), csrfToken);
     * 		    request.setAttribute(csrfToken.getParameterName(), csrfToken);
     *
     *          //TODO,判断是否需要csrf保护的请求;默认实现是: "GET", "HEAD", "TRACE", "OPTIONS"请求不需要csrf保护
     * 		    if (!this.requireCsrfProtectionMatcher.matches(request)) {
     * 			    filterChain.doFilter(request, response);
     * 			    return;
     *          }
     *
     *          //TODO,从Request的header/param中取 token
     * 		    String actualToken = request.getHeader(csrfToken.getHeaderName());
     * 		    if (actualToken == null) {
     * 			    actualToken = request.getParameter(csrfToken.getParameterName());
     *          }
     *          //TODO,比较CsrfTokenRepository中的token 和 Request带过来的token
     * 		    if (!csrfToken.getToken().equals(actualToken)) {//TODO, 1、如果是第一个请求,Request的Token肯定是null; 2、前端调用logout退出登录,将清空csrf token; 3、认证成功后将重新生成csrfToken; 4、使用remember-me登录成功后重新生成csrfToken; 5、因为不明原因两者不相等
     * 		                                     //TODO,针对1:前端在启动时调用后端的一个初始化接口(GET),用于第一次生成csrfToken; 针对2:前端调用logout接口后，可以调用一次初始化接口重新生成csrfToken; 针对3:前端每次调用认证接口后都需要重新读取csrfToken; 针对4:前端每次调用任何接口后都需要重新读取csrfToken或者在调用任何接口前先读取csrfToken; 针对5:后端遇到此异常，将写给前端一个code，前端需要处理此code，可以重新调用初始化接口
     * 		                                     //整体来说: 1、前置处理:在调用任何接口前先读取csrfToken,如果没有调用初始化接口获取；2、后置处理:前端第一个请求调用初始化接口，之后没调用一个接口，都将读取csrfToken缓存
     * 			    if (missingToken) {
     * 				    this.accessDeniedHandler.handle(request, response, new MissingCsrfTokenException(actualToken));
     *              } else {
     * 				    this.accessDeniedHandler.handle(request, response, new InvalidCsrfTokenException(csrfToken, actualToken));
     *              }
     * 			    return;
     *          }
     * 		    filterChain.doFilter(request, response);
     * 		}
     *}
     *使用CookieCsrfTokenRepository
     * csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
     *csrf与logout
     * csrf()配置将会在logout的LogoutHandler中增加一个CsrfLogoutHandler，并且将csrfTokenRepository(CsrfTokenRepository)配置的CsrfTokenRepository写入CsrfLogoutHandler
     * 当退出登录时，清空csrf: CsrfTokenRepository.saveToken(null, request, response);
     *csrf与Authentication
     * csrf()配置将会在SessionAuthenticationStrategy中增加一个CsrfAuthenticationStrategy: 清空csrfToken并重新生成新的csrfToken
     * 该CsrfAuthenticationStrategy会被同时写到AbstractAuthenticationProcessingFilter 和  SessionManagementFilter
     *
     *
     *
     *第五: logout
     *
     *一般配置
     *.logout()
     *.logoutUrl("/logout")//logout接口地址
     *.logoutSuccessHandler((req, resp, authentication) -> {      //配置LogoutSuccessHandler
     *     resp.setContentType("application/json; charset=utf-8");
     *     PrintWriter out = resp.getWriter();
     *     out.write(objectMapper.writeValueAsString(JsonResult.buildSuccessResult("注销成功")));
     *     out.flush();
     *     out.close();
     * })
     * .deleteCookies("s-token")                //相当于配置了CookieClearingLogoutHandler
     * .clearAuthentication(true)               //SecurityContextLogoutHandler.setClearAuthentication(true)
     * .invalidateHttpSession(true)             //SecurityContextLogoutHandler.setInvalidateHttpSession(true)
     * .permitAll()
     *
     *LogoutFilter {
     *    RequestMatcher logoutRequestMatcher;
     *    //CompositeLogoutHandler类型: List<LogoutHandler> logoutHandlers;
     *    final LogoutHandler handler;
     *    final LogoutSuccessHandler logoutSuccessHandler;
     *
     *    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
     * 		  HttpServletRequest request = (HttpServletRequest) req;
     * 		  HttpServletResponse response = (HttpServletResponse) res;
     *        //logoutRequestMatcher
     * 		  if (requiresLogout(request, response)) {
     * 			  Authentication auth = SecurityContextHolder.getContext().getAuthentication();
     *            //LogoutHandler 执行
     * 			  this.handler.logout(request, response, auth);
     *            //LogoutSuccessHandler 执行
     * 			  logoutSuccessHandler.onLogoutSuccess(request, response, auth);
     * 			  return;
     * 		  }
     * 		  chain.doFilter(request, response);
     *    }
     *}
     *
     *LogoutHandler
     * PersistentTokenBasedRememberMeServices  @see remember-me/6
     * TokenBasedRememberMeServices            @see remember-me/6
     * CookieClearingLogoutHandler             清空指定cookie
     * CsrfLogoutHandler                       @see csrf
     * SecurityContextLogoutHandler            默认设置，用于注销HttpSession(session.invalidate();)和清空当前线程SecurityContext
     *
     *
     *
     *第六: pre-authentication
     *
     *AbstractPreAuthenticatedProcessingFilter { define processor of pre-authenticated authentication, which assumed that the principal has already been authenticated by external system(外部系统),eg: 从X509证书中取出来的principal
     *    AuthenticationManager authenticationManager = null;
     *    boolean continueFilterChainOnUnsuccessfulAuthentication = true;
     * 	  boolean checkForPrincipalChanges;
     * 	  boolean invalidateSessionOnPrincipalChange = true;
     * 	  AuthenticationSuccessHandler authenticationSuccessHandler = null;
     * 	  AuthenticationFailureHandler authenticationFailureHandler = null;
     *
     *    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
     * 		 //返回true,执行认证
     * 		 if (requiresAuthentication((HttpServletRequest) request)) {
     * 			 doAuthenticate((HttpServletRequest) request, (HttpServletResponse) response);
     *       }
     * 		 chain.doFilter(request, response);
     * 	  }
     *
     *    private void doAuthenticate(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
     * 		Authentication authResult;
     * 	    //子类实现
     * 		Object principal = getPreAuthenticatedPrincipal(request);
     * 	    //子类实现
     * 		Object credentials = getPreAuthenticatedCredentials(request);
     * 		if (principal == null) {
     * 			return;
     * 		}
     * 		try {
     * 			PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(principal, credentials);
     * 			authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
     * 			//TODO,使用AuthenticationManager认证 PreAuthenticatedAuthenticationToken，PreAuthenticatedAuthenticationProvider
     * 			authResult = authenticationManager.authenticate(authRequest);
     * 			successfulAuthentication(request, response, authResult);
     *      } catch (AuthenticationException failed) {
     * 			unsuccessfulAuthentication(request, response, failed);
     * 			if (!continueFilterChainOnUnsuccessfulAuthentication) {
     * 				throw failed;
     *           }
     *      }
     *    }
     *}
     *X509AuthenticationFilter {
     *    //从x509证书中获取principal
     *    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request);
     *    //从x509证书中获取credentials
     *    protected Object getPreAuthenticatedCredentials(HttpServletRequest request);
     *}
     *TODO?Jaas,X509,Run-As,Saml2
     *
     *
     *
     *第七: Authenticate
     *
     *AbstractAuthenticationProcessingFilter: define processor of browser-based HTTP-based authentication requests
     * public abstract class AbstractAuthenticationProcessingFilter {
     *      //TODO,认证处理类
     *      private AuthenticationManager authenticationManager;
     *      //TODO,Request路径匹配器: boolean matches(HttpServletRequest)
     *      RequestMatcher requiresAuthenticationRequestMatcher;
     *      //TODO,Session管理类
     *      SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();
     *
     *      //TODO,remember-me处理类
     *      RememberMeServices rememberMeServices = new NullRememberMeServices();
     *      boolean continueChainBeforeSuccessfulAuthentication = false; //true-认证成功后继续执行拦截器链
     *      AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler(); //默认设置的类将执行redirect to defaultSuccessUrl or pre page
     *      AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();  //默认设置的类将执行redirect to defaultFailureUrl
     *
     *  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
     *
     * 		HttpServletRequest request = (HttpServletRequest) req;
     * 		HttpServletResponse response = (HttpServletResponse) res;
     *
     *      //TODO,使用RequestMatcher.match(request)返回true，则将会使用此filter执行认证，否则(false)继续执行chain
     *      //TODO,在UsernamePasswordAuthenticationFilter中，只有登录接口才会返回true，进而执行filter中认证逻辑
     * 		if (!requiresAuthentication(request, response)) {
     * 			chain.doFilter(request, response);
     * 			return;
     *      }
     *
     * 		Authentication authResult;
     * 		try {
     * 	        //TODO,1、执行认证，需要在子类中是实现
     * 			authResult = attemptAuthentication(request, response);
     * 			if (authResult == null) {
     * 				return;
     *          }
     *          //TODO,2、使用SessionAuthenticationStrategy处理session, @see SessionAuthenticationStrategy
     * 			sessionStrategy.onAuthentication(authResult, request, response);
     *       } catch (InternalAuthenticationServiceException failed) {
     *          //TODO,3.1、认证失败，当前线程清空Authentication,remember-me处理,使用AuthenticationFailureHandler响应客户端
     * 			unsuccessfulAuthentication(request, response, failed);
     * 		    //直接return ，而不是chain.doFilter
     * 			return;
     *       } catch (AuthenticationException failed) {
     * 			//TODO,3.2、认证失败，当前线程清空Authentication,remember-me处理,使用AuthenticationFailureHandler响应客户端
     * 			unsuccessfulAuthentication(request, response, failed);
     * 			return;
     *       }
     * 		//TODO,4.1、认证成功，继续执行拦截器链
     * 		if (continueChainBeforeSuccessfulAuthentication) {
     * 			chain.doFilter(request, response);
     *      }
     *      //TODO,4.2、认证成功，在当前线程设置Authentication,remember-me处理,使用AuthenticationSuccessHandler响应客户端
     * 		successfulAuthentication(request, response, chain, authResult);
     * 	  }
     *
     *  }
     *
     *UsernamePasswordAuthenticationFilter: 基于form表单的username,password形式认证实现
     * public class UsernamePasswordAuthenticationFilter {
     *
     *   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
     *          throws AuthenticationException {
     *
     *      //request.getParameter形式获取参数
     * 		String username = obtainUsername(request);
     * 		String password = obtainPassword(request);
     * 		if (username == null) {
     * 			username = "";
     *      }
     * 		if (password == null) {
     * 			password = "";
     *      }
     * 		username = username.trim();
     *      //TODO,1、构造UsernamePasswordAuthenticationToken
     * 		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
     * 		setDetails(request, authRequest);
     *      //TODO,2、使用AuthenticationManager执行认证: UsernamePasswordAuthenticationToken DaoAuthenticationProvider
     * 		return this.getAuthenticationManager().authenticate(authRequest);
     * 	 }
     *
     * }
     *
     *AuthenticationManager
     * public interface AuthenticationManager {
     *     Authentication authenticate(Authentication authentication) throws AuthenticationException;
     * }
     * 1、Authentication作为AuthenticationManager的输入，提供待认证的用户信息，此时isAuthenticated() returns false
     *    Authentication代表已认证的用户信息，保存在SecurityContext中，此时isAuthenticated() returns true
     * 2、执行认证逻辑，返回认证成功的Authentication，如果认证失败，抛出异常
     *
     *ProviderManager: AuthenticationManager的实现类
     * public class ProviderManager implements AuthenticationManager {
     *   private List<AuthenticationProvider> providers;
     *   private AuthenticationManager parent;
     *
     *   public Authentication authenticate(Authentication authentication) throws AuthenticationException {
     * 		Class<? extends Authentication> toTest = authentication.getClass();
     * 		AuthenticationException lastException = null;
     * 		AuthenticationException parentException = null;
     * 		Authentication result = null;
     * 		Authentication parentResult = null;
     *
     *      //TODO,1、遍历List<AuthenticationProvider>，尝试使用(按顺序)使用每一个AuthenticationProvider
     * 		for(AuthenticationProvider provider : getProviders()) {
     * 			if (!provider.supports(toTest)) {//TODO,1.1、如果supports=false,直接下一个
     * 				continue;
     *          }
     * 			try {
     * 	            //TODO,1.2、使用AuthenticationProvider执行认证
     * 				result = provider.authenticate(authentication);
     * 				if (result != null) { //TODO,1.3、如果返回值不为null,执行break，不会尝试剩余的AuthenticationProvider
     * 					copyDetails(authentication, result);
     * 					break;
     *              }
     *          } catch (AccountStatusException e) {
     *              //TODO,1.4、如果使用某一个AuthenticationProvider时，遇到AccountStatusException，则抛出去
     * 				prepareException(e, authentication);
     * 				throw e;
     *          } catch (InternalAuthenticationServiceException e) {
     *              //TODO,1.5、如果使用某一个AuthenticationProvider时，遇到InternalAuthenticationServiceException，则抛出去
     * 				prepareException(e, authentication);
     * 				throw e;
     *         } catch (AuthenticationException e) {
     *              //TODO,1.6、如果使用某一个AuthenticationProvider时，遇到AuthenticationException，保存异常对象，不向外抛，此时result=null
     * 				lastException = e;
     *         }
     *      }
     *      //TODO,2、result=null的场景: List<AuthenticationProvider>没有一个supports或者supports的发生AuthenticationException异常
     * 		if (result == null && parent != null) {
     * 	        //TODO,2.1、如果parent!=null，使用parent
     * 			try {
     * 				result = parentResult = parent.authenticate(authentication);
     *          } catch (ProviderNotFoundException e) {
     *          } catch (AuthenticationException e) {
     * 				lastException = parentException = e;
     *          }
     *      }
     * 		if (result != null) {
     * 			if (eraseCredentialsAfterAuthentication && (result instanceof CredentialsContainer)) {
     * 				((CredentialsContainer) result).eraseCredentials();
     *          }
     *          ...
     * 			return result;
     *      }
     *      //parent is null or parent认证抛异常
     * 		throw lastException;
     *    }
     * }
     *
     *
     *AuthenticationProvider
     * public interface AuthenticationProvider {
     *     Authentication authenticate(Authentication authentication) throws AuthenticationException;
     *     boolean supports(Class<?> authentication); //根据Authentication实现类的Class判定
     * }
     *1、DaoAuthenticationProvider    supports UsernamePasswordAuthenticationToken
     * public class DaoAuthenticationProvider {
     *     private PasswordEncoder passwordEncoder; //TODO,密码加密器
     *     private UserDetailsService userDetailsService; //TODO,UserDetailsService实现
     *     private UserDetailsPasswordService userDetailsPasswordService;
     *
     *     //TODO, supports UsernamePasswordAuthenticationToken
     *     public boolean supports(Class<?> authentication) {
     * 		    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
     *     }
     *     public Authentication authenticate(Authentication authentication) throws AuthenticationException {
     * 		    String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
     * 			try {
     * 				user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
     *          } catch (UsernameNotFoundException notFound) {
     * 				if (hideUserNotFoundExceptions) {
     * 					throw new BadCredentialsException(messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
     * 							"Bad credentials"));
     *              } else throw notFound;
     *          }
     * 		    try {
     * 			    preAuthenticationChecks.check(user);
     * 			    //TODO,校验password是否正确
     * 			    additionalAuthenticationChecks(user,(UsernamePasswordAuthenticationToken) authentication);
     *          } catch (AuthenticationException exception) {
     * 			    ...
     *          }
     *        }
     * 		  return createSuccessAuthentication(principalToReturn, authentication, user);
     *      }
     *      protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
     * 			throws AuthenticationException {
     * 		    prepareTimingAttackProtection();
     * 		    try {
     * 		        //TODO,使用UserDetailsService加载UserDetails
     * 			    UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
     * 			    if (loadedUser == null) {
     * 				    throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation");
     *              }
     * 			    return loadedUser;
     * 			} catch (UsernameNotFoundException ex) {
     * 			    mitigateAgainstTimingAttack(authentication);
     * 			    throw ex;
     *          } catch (InternalAuthenticationServiceException ex) {
     * 			    throw ex;
     *          } catch (Exception ex) {
     * 			    throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
     *          }
     *    }
     *
     * }
     *2、RememberMeAuthenticationProvider  supports RememberMeAuthenticationToken
     * public class RememberMeAuthenticationProvider {
     *     String key;  //此key为AbstractRememberMeServices中key
     *
     *     public boolean supports(Class<?> authentication) {
     * 		  return (RememberMeAuthenticationToken.class.isAssignableFrom(authentication));
     *     }
     *     public Authentication authenticate(Authentication authentication) throws AuthenticationException {
     * 		  if (!supports(authentication.getClass())) {
     * 			  return null;
     *        }
     * 		  if (this.key.hashCode() != ((RememberMeAuthenticationToken) authentication).getKeyHash()) {
     * 			  throw new BadCredentialsException(
     * 					messages.getMessage("RememberMeAuthenticationProvider.incorrectKey",
     * 							"The presented RememberMeAuthenticationToken does not contain the expected key"));
     *        }
     * 		  return authentication;
     * 	   }
     * }
     *3、PreAuthenticatedAuthenticationProvider  supports PreAuthenticatedAuthenticationToken
     * public class PreAuthenticatedAuthenticationProvider {
     *     AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> preAuthenticatedUserDetailsService = null;
     *
     *     public final boolean supports(Class<?> authentication) {
     * 		  return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
     *     }
     *     public Authentication authenticate(Authentication authentication) throws AuthenticationException {
     * 		 if (!supports(authentication.getClass())) return null;
     *
     * 		 if (authentication.getPrincipal() == null) {
     * 			 if (throwExceptionWhenTokenRejected) {
     * 				throw new BadCredentialsException("No pre-authenticated principal found in request.");
     *           }
     * 			 return null;
     *       }
     * 		 if (authentication.getCredentials() == null) {
     * 			 if (throwExceptionWhenTokenRejected) {
     * 				throw new BadCredentialsException("No pre-authenticated credentials found in request.");
     *           }
     * 			 return null;
     *       }
     *       //TODO,使用AuthenticationUserDetailsService加载UserDetails
     * 		 UserDetails ud = preAuthenticatedUserDetailsService.loadUserDetails((PreAuthenticatedAuthenticationToken) authentication);
     * 		 userDetailsChecker.check(ud);
     *
     * 		 PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(ud, authentication.getCredentials(), ud.getAuthorities());
     * 		 result.setDetails(authentication.getDetails());
     * 		 return result;
     * 	  }
     * }
     *
     *
     *第八: remember-me
     *
     *1、RememberMeServices {
     *     Authentication autoLogin(HttpServletRequest request, HttpServletResponse response);
     *     void loginFail(HttpServletRequest request, HttpServletResponse response);
     *     void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication);
     *}
     *1)、AbstractRememberMeServices{
     *     UserDetailsService userDetailsService;
     *     cookieName="remember-me"
     *     parameter="remember-me"
     *     String key;
     *     tokenValiditySeconds=1209600
     *     Boolean useSecureCookie = null;
     *     GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
     *     @Override
     *     public final Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
     * 		  //TODO,从cookie中获取remember-me token
     * 		  String rememberMeCookie = extractRememberMeCookie(request);
     * 		  if (rememberMeCookie == null) return null;
     * 		  if (rememberMeCookie.length() == 0) {//如果cookie无效，使用response取消掉cookie
     * 			  logger.debug("Cookie was empty");
     * 			  cancelCookie(request, response);
     * 			  return null;
     *        }
     * 		  UserDetails user = null;
     * 		  try {
     * 			  String[] cookieTokens = decodeCookie(rememberMeCookie);
     * 			  //TODO,子类实现
     * 			  user = processAutoLoginCookie(cookieTokens, request, response);
     * 			  userDetailsChecker.check(user);
     *
     *            //TODO,remember-me认证成功，返回RememberMeAuthenticationToken{key=this.key, principal=UserDetails, authoritiesMapper.mapAuthorities(user.getAuthorities())}
     * 			  return createSuccessfulAuthentication(request, user);
     *        } catch (CookieTheftException cte) {
     * 			  cancelCookie(request, response);
     * 			  throw cte;
     *        } catch (UsernameNotFoundException noUser) {
     * 			  logger.debug("Remember-me login was valid but corresponding user not found.", noUser);
     *        } catch (InvalidCookieException invalidCookie) {
     * 			  logger.debug("Invalid remember-me cookie: " + invalidCookie.getMessage());
     *        } catch (AccountStatusException statusInvalid) {
     * 			  logger.debug("Invalid UserDetails: " + statusInvalid.getMessage());
     *        } catch (RememberMeAuthenticationException e) {
     * 			  logger.debug(e.getMessage());
     *        }
     * 		  cancelCookie(request, response);
     * 		  return null;
     *    }
     *    public final void loginFail(HttpServletRequest request, HttpServletResponse response) {
     * 		  cancelCookie(request, response);
     * 		  //TODO,子类实现
     * 		  onLoginFail(request, response);
     *    }
     *    public final void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
     * 		  //request.getParameter(parameter);formData格式的remember-me 参数
     * 		  if (!rememberMeRequested(request, parameter)) {
     * 			  return;
     *        }
     *        //TODO,子类实现
     * 		  onLoginSuccess(request, response, successfulAuthentication);
     * 	  }
     *}
     *2)、TokenBasedRememberMeServices{
     *     UserDetails processAutoLoginCookie(cookieTokens, request, response){
     *         username = cookieTokens[0];
     *         tokenExpiryTime = cookieTokens[1];
     *         clientHashValue = cookieTokens[2];
     *
     *         userDetails = userDetailsService.loadUserByUsername(username);
     *         serverHashValue = Base64的encode:  username:tokenExpiryTime:password+key
     *         if clientHashValue==serverHashValue 则返回UserDetails
     *     }
     *}
     *3)、PersistentTokenBasedRememberMeServices{
     *     PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();
     *     SecureRandom random;
     *     seriesLength = 16;
     *     tokenLength = 16;
     *
     *     public UserDetails processAutoLoginCookie(cookieTokens, request, response){
     *          presentedSeries = cookieTokens[0];  //series
     *          presentedToken = cookieTokens[1];   //token
     *
     *          //根据series获取PersistentRememberMeToken
     *          PersistentRememberMeToken token = tokenRepository.getTokenForSeries(presentedSeries);
     *          if  presentedToken != token.getTokenValue() {
     * 			    tokenRepository.removeUserTokens(token.getUsername());
     *              throw new CookieTheftException(
     * 					messages.getMessage(Invalid remember-me token));
     *          }
     *          if (token.getDate().getTime() + getTokenValiditySeconds() * 1000L < System.currentTimeMillis()) {
     *              //remember-me token过期了，此此处没有使用tokenRepository.removeUserTokens(token.getUsername());
     * 			    throw new RememberMeAuthenticationException("Remember-me login has expired");
     *          }
     *          //series不变，tokenValue重新生成
     *          PersistentRememberMeToken newToken = new PersistentRememberMeToken(token.getUsername(), token.getSeries(), generateTokenData(), new Date());
     *          //更新新的token
     *          tokenRepository.updateToken(newToken.getSeries(), newToken.getTokenValue(), newToken.getDate());
     *          //将新的token写到cookie
     *          addCookie(newToken, request, response);
     *
     *          return userDetailsService.loadUserByUsername(token.getUsername());
     *     }
     *     protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
     * 		  String username = successfulAuthentication.getName();
     * 		  //TODO,认证成功后，生成series,token，创建remember-me Token
     * 		  PersistentRememberMeToken persistentToken = new PersistentRememberMeToken(username, generateSeriesData(), generateTokenData(), new Date());
     * 	      //TODO,在PersistentTokenRepository中保存remember-me Token
     * 	      tokenRepository.createNewToken(persistentToken);
     * 		  //TODO,将remember-me Token写到cookie
     * 		  addCookie(persistentToken, request, response);
     *     }
     *}
     *3.1)、PersistentRememberMeToken{
     *        final String username;
     * 	      final String series;
     * 	      final String tokenValue;
     * 	      final Date date;
     *     }
     *3.2)、PersistentTokenRepository{
     *     void createNewToken(PersistentRememberMeToken);
     *     updateToken(String series, String tokenValue, Date lastUsed);
     *     PersistentRememberMeToken getTokenForSeries(String seriesId);
     *     void removeUserTokens(String username);
     *}
     *
     *4、如果配置rememberMe()，将开启rememberMe功能，chain中将设置RememberMeAuthenticationFilter
     * tokenRepository(inMemoryTokenRepositoryImpl())将使用PersistentTokenBasedRememberMeServices和InMemoryTokenRepositoryImpl
     * 并且AbstractAuthenticationProcessingFilter,RememberMeAuthenticationFilter中均注入相同的PersistentTokenBasedRememberMeServices实现
     * other: tokenRepository(flRedisTokenRepository())使用FlRedisTokenRepositoryImpl替代InMemoryTokenRepositoryImpl
     *
     *AbstractAuthenticationProcessingFilter中{
     *     认证成功
     *     rememberMeServices.loginSuccess(request, response, Authentication);
     *     认证失败
     *     rememberMeServices.loginFail(request, response);
     *}
     *RememberMeAuthenticationFilter{
     *  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
     * 		HttpServletRequest request = (HttpServletRequest) req;
     * 		HttpServletResponse response = (HttpServletResponse) res;
     *
     *      //当前线程中的Authentication==null时
     * 		if (SecurityContextHolder.getContext().getAuthentication() == null) {
     * 	        //remember-me login
     * 			Authentication rememberMeAuth = rememberMeServices.autoLogin(request, response);
     *
     * 			if (rememberMeAuth != null) {
     * 				try {
     * 			        //TODO,使用AuthenticationManager认证: RememberMeAuthenticationProvider RememberMeAuthenticationToken
     * 					rememberMeAuth = authenticationManager.authenticate(rememberMeAuth);
     * 					//TODO,Store to SecurityContextHolder, remember-me认证没有走SessionAuthenticationStrategy流程
     * 					SecurityContextHolder.getContext().setAuthentication(rememberMeAuth);
     * 					onSuccessfulAuthentication(request, response, rememberMeAuth);
     * 					if (successHandler != null) {//TODO,建议是不设置(默认没有设置),因为还需要到SessionManagementFilter中执行SessionAuthenticationStrategy流程
     * 						successHandler.onAuthenticationSuccess(request, response, rememberMeAuth);
     * 						return;
     *                  }
     *              } catch (AuthenticationException authenticationException) {
     * 					rememberMeServices.loginFail(request, response);
     * 					onUnsuccessfulAuthentication(request, response, authenticationException);
     *              }
     *          }
     * 			chain.doFilter(request, response);
     *      } else {
     * 			chain.doFilter(request, response);
     *      }
     *  }
     *}
     *5、other
     * 默认AbstractRememberMeServices中通过request.getParameter["remember-me"]取remember-me参数，如果带有此参数设置了并且值为true,on,yes,1，onLoginSuccess才会执行
     * Authentication成功后触发RememberMeServices的loginSuccess，将会生成remember-me Token
     * 使用RememberMeAuthenticationFilter执行RememberMeServices的autoLogin后，保持series不变，token重新生成
     *6、logout
     * AbstractRememberMeServices implements LogoutHandler
     * 会被设置到LogoutFilter的logoutHandler中，当logout时，执行
     * public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
     * 		//清空remember-me的cookie
     * 		cancelCookie(request, response);
     * }
     * PersistentTokenBasedRememberMeServices中重写
     * @Override
     * public void logout(HttpServletRequest request, HttpServletResponse response,
     * 			Authentication authentication) {
     * 		super.logout(request, response, authentication);
     * 	    //清空TokenRepository
     * 		if (authentication != null) {
     * 			tokenRepository.removeUserTokens(authentication.getName());
     *      }
     *  }
     *
     *
     *
     *第九: AnonymousAuthenticationFilter
     *AuthenticationTrustResolver{
     *   boolean isAnonymous(Authentication);
     *   boolean isRememberMe(Authentication);
     *}
     *AuthenticationTrustResolverImpl{
     *   ...
     *}
     *AnonymousAuthenticationFilter
     * 默认设置在chain
     * AnonymousAuthenticationProvider被设置在ProviderManager的List<AuthenticationProvider>
     * 如果没有认证信息，写入默认的Authentication
     * public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
     * 			throws IOException, ServletException {
     *      //写入AnonymousAuthenticationToken到当前线程，注意不会用到SecurityContextRepository
     * 		if (SecurityContextHolder.getContext().getAuthentication() == null) {
     * 			SecurityContextHolder.getContext().setAuthentication(createAuthentication((HttpServletRequest) req));
     *
     * 		chain.doFilter(req, res);
     * }
     *
     *
     *第十: session-management
     *
     *SessionAuthenticationStrategy
     *1、默认实现类是CompositeSessionAuthenticationStrategy
     *public class CompositeSessionAuthenticationStrategy {
     *     private final List<SessionAuthenticationStrategy> delegateStrategies;
     *     //TODO,如下，循环delegateStrategies
     *     for (SessionAuthenticationStrategy delegate : this.delegateStrategies) {
     * 			delegate.onAuthentication(authentication, request, response);
     * 	   }
     *}
     *2、CompositeSessionAuthenticationStrategy会被同时写入到AbstractAuthenticationProcessingFilter和SessionManagementFilter
     *
     *3、session-fixation protection attack prevention(固定会话保护)
     *   sessionFixation().migrateSession();  将使用SessionFixationProtectionStrategy: //创建new session并将old session的all existing attributes拷贝到new session
     *   sessionFixation().changeSessionId(); 将使用ChangeSessionIdAuthenticationStrategy: //修改sessionId
     * 默认不提供配置的话，内部会判断如果>servlet 3.1就是用changeSessionId()，否则migrateSession()
     * 所以，ChangeSessionIdAuthenticationStrategy/SessionFixationProtectionStrategy会保存在CompositeSessionAuthenticationStrategy
     *
     *
     *4、"用户同时在线数量控制"和"会话失效"
     * 如果配置了maximumSessions(1)，在CompositeSessionAuthenticationStrategy会增加两个
     *1)、ConcurrentSessionControlAuthenticationStrategy {
     *      final SessionRegistry sessionRegistry; //TODO,实现类是SessionRegistryImpl
     *
     *      public void onAuthentication(Authentication authentication,
     * 			    HttpServletRequest request, HttpServletResponse response) {
     *
     * 	        //TODO,使用SessionRegistry获取Principal的所有Session信息
     * 		    final List<SessionInformation> sessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
     *          //TODO,执行"用户同时在线数量控制"代码;1、抛出异常，进而阻止登录成功;2、将sessions中一个SessionInformation设置为失效
     *          ...
     * 	    }
     *   }
     *2)、RegisterSessionAuthenticationStrategy {
     *      //TODO,实现类是SessionRegistryImpl
     *      final SessionRegistry sessionRegistry;
     *      //TODO,使用SessionRegistry保存Session信息
     *      public void onAuthentication(Authentication authentication,
     * 			    HttpServletRequest request, HttpServletResponse response) {
     * 		    sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());
     *      }
     *   }
     *public class SessionRegistryImpl {
     *     //保存Principal:Set<sessionId>, principal即Authentication中的principal 注意是非static变量
     *     final ConcurrentMap<Object, Set<String>> principals = new ConcurrentHashMap<>();
     *     //保存sessionId:SessionInformation   注意是非static变量
     *     final Map<String, SessionInformation> sessionIds = new ConcurrentHashMap<>();
     *     //根据principal获取所有的Session信息
     *     List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions);
     *     //根据sessionId获取Session信息
     *     getSessionInformation(String sessionId);
     *     //响应Session注销事件
     *     onApplicationEvent(SessionDestroyedEvent);
     *     //保存
     *     registerNewSession(String sessionId, Object principal);
     *}
     *TODO,内存泄漏问题,如果重复登录，并且携带上一次调用的s-token,将会导致SessionRegistryImpl中数据无法清理
     *TODO,重复登录，每次不携带s-token,新生成HttpSession,被顶掉的HttpSession还在，对应的SessionRegistryImpl打上过期标记,如果HttpSession超时注销，SessionRegistryImpl可以响应此事件
     *TODO,登录成功，返回s-token和remember-me，HttpSession and SessionRegistryImpl(false),此时不带s-token,使用remember-me访问非登录接口(将触发remember-me登录),新生成HttpSession,被顶掉的HttpSession还在，对应的SessionRegistryImpl打上过期标记,如果HttpSession超时注销，SessionRegistryImpl可以响应此事件
     *
     *
     *3)、ConcurrentSessionFilter
     * 如果配置了maximumSessions(1),在chain中增加拦截器，用于配合 4、"用户同时在线数量控制"和"会话失效"
     * public class ConcurrentSessionFilter {
     *      //即上述SessionRegistryImpl
     *      final SessionRegistry sessionRegistry;
     *      //SecurityContextLogoutHandler
     * 	    LogoutHandler handlers = new CompositeLogoutHandler(new SecurityContextLogoutHandler());
     * 	    //Session失效处理类
     * 	    SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
     *
     *      public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
     * 			throws IOException, ServletException {
     * 		   HttpServletRequest request = (HttpServletRequest) req;
     * 		   HttpServletResponse response = (HttpServletResponse) res;
     *
     *         //TODO,1、从Request获取Session
     * 		   HttpSession session = request.getSession(false);
     * 		   if (session != null) {
     * 		       //TODO,2、从SessionRegistry获取Session信息
     * 			   SessionInformation info = sessionRegistry.getSessionInformation(session.getId());
     * 			   if (info != null) {
     * 				  if (info.isExpired()) {
     * 				      //TODO,3.1、使用SecurityContextLogoutHandler，将HttpSession销毁(session.invalidate();HttpSessionEventPublisher实现HttpSessionListener响应servlet的HttpSession销毁事件，再通过spring的ApplicationEventPublisher.publish将事件发布到spring容器,SessionRegistry监听此事件后将对应的SessionInformation删掉); 将当前线程Authentication删除
     * 					  doLogout(request, response);
     * 					  this.sessionInformationExpiredStrategy.onExpiredSessionDetected(new SessionInformationExpiredEvent(info, request, response));
     * 					  return;
     * 				  } else {
     * 					  sessionRegistry.refreshLastRequest(info.getSessionId());
     *                }
     *            }
     *         }
     * 		   chain.doFilter(request, response);
     * 		}
     * }
     *5、如果配置了csrf()，将增加CsrfAuthenticationStrategy
     * 并且将csrfTokenRepository(CookieCsrfTokenRepository)的CookieCsrfTokenRepository写入CsrfAuthenticationStrategy
     * public class CsrfAuthenticationStrategy{
     *      CsrfTokenRepository csrfTokenRepository;
     *
     *      public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
     * 					throws SessionAuthenticationException {
     * 		    boolean containsToken = this.csrfTokenRepository.loadToken(request) != null;
     * 		    if (containsToken) {
     * 		        //TODO,1、清空csrfToken
     * 			    this.csrfTokenRepository.saveToken(null, request, response);
     *              //TODO,2、重新生成并保存csrfToken
     * 			    CsrfToken newToken = this.csrfTokenRepository.generateToken(request);
     * 			    this.csrfTokenRepository.saveToken(newToken, request, response);
     * 			    request.setAttribute(CsrfToken.class.getName(), newToken);
     * 			    request.setAttribute(newToken.getParameterName(), newToken);
     *          }
     *      }
     * }
     *
     *6、在AbstractAuthenticationProcessingFilter中
     *    authResult = attemptAuthentication(request, response);
     *  //TODO,一旦认证成功，即执行SessionAuthenticationStrategy
     * 	  sessionStrategy.onAuthentication(authResult, request, response);
     *
     *7、在SessionManagementFilter中
     * public class SessionManagementFilter {
     *      //TODO,和SecurityContextPersistenceFilter一致
     *      final SecurityContextRepository securityContextRepository;
     * 	    SessionAuthenticationStrategy sessionAuthenticationStrategy;
     * 	    AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
     * 	    InvalidSessionStrategy invalidSessionStrategy = null;
     * 	    AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
     *
     * 	  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
     * 			throws IOException, ServletException {
     * 		HttpServletRequest request = (HttpServletRequest) req;
     * 		HttpServletResponse response = (HttpServletResponse) res;
     *
     * 		if (request.getAttribute(FILTER_APPLIED) != null) {
     * 			chain.doFilter(request, response);
     * 			return;
     *      }
     * 		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
     *
     *      //TODO,1、如果SecurityContextRepository检测SecurityContext不存在
     * 		if (!securityContextRepository.containsContext(request)) {
     * 	        //TODO,2、从当前线程获取Authentication,并且不是anonymous,eg: remember-me的autoLogin
     * 			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
     * 			if (authentication != null && !trustResolver.isAnonymous(authentication)) {
     * 				try {
     * 			        //TODO,3、如果不是anonymous用户，则执行SessionAuthenticationStrategy
     * 					sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
     *              } catch (SessionAuthenticationException e) {
     * 					SecurityContextHolder.clearContext();
     * 					failureHandler.onAuthenticationFailure(request, response, e);
     * 					return;
     *              }
     *              //TODO,5、SecurityContextRepository,保存SecurityContext
     * 				securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);
     *          } else {
     * 				// No security context or authentication present. Check for a session
     * 				if (request.getRequestedSessionId() != null
     * 						&& !request.isRequestedSessionIdValid()) {
     * 					//TODO,6、如果session invalid
     * 					if (invalidSessionStrategy != null) {
     * 						invalidSessionStrategy.onInvalidSessionDetected(request, response);
     * 						return;
     *                  }
     *              }
     *          }
     *      }
     * 		chain.doFilter(request, response);
     * 	  }
     * }
     *
     *
     *
     *第十一: ExceptionTranslationFilter
     *
     *ExceptionTranslationFilter，处理AuthenticationException或者AccessDeniedException thrown within the filter chain
     * 如果是AuthenticationException or AccessDeniedException and anonymous using AuthenticationEntryPoint
     * 否则对AccessDeniedException,using AccessDeniedHandler
     * public class ExceptionTranslationFilter {
     *     AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();
     * 	   AuthenticationEntryPoint authenticationEntryPoint;
     * 	   AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
     * 	   ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
     * 	   RequestCache requestCache = new HttpSessionRequestCache();
     *     final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
     *
     *     public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
     * 			throws IOException, ServletException {
     * 		HttpServletRequest request = (HttpServletRequest) req;
     * 		HttpServletResponse response = (HttpServletResponse) res;
     *
     * 		try {
     * 	        //TODO,1、执行拦截器链
     * 			chain.doFilter(request, response);
     *      } catch (IOException ex) {
     * 			throw ex;
     *      } catch (Exception ex) {
     * 			Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
     * 			RuntimeException ase = (AuthenticationException) throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);
     * 			if (ase == null) {
     * 				ase = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
     *          }
     * 			if (ase != null) {
     * 			    //TODO,2、如果是AuthenticationException or AccessDeniedException
     * 				if (response.isCommitted()) {
     * 					throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", ex);
     *              }
     *              //TODO,3、处理AuthenticationException or AccessDeniedException
     * 				handleSpringSecurityException(request, response, chain, ase);
     *          } else {
     * 				if (ex instanceof ServletException) {
     * 					throw (ServletException) ex;
     *              } else if (ex instanceof RuntimeException) {
     * 					throw (RuntimeException) ex;
     *              }
     * 				throw new RuntimeException(ex);
     *          }
     *        }
     *    }
     * }
     *
     *
     *
     *第十二: Authorize
     * 授权: 资源权限校验
     *
     *1、GrantedAuthority {
     *    String getAuthority(); //直接就是String
     *}
     *2、Pre-Invocation: 前置执行
     *1)、AccessDecisionManager {
     *    boolean supports(ConfigAttribute attribute);
     *    boolean supports(Class<?> clazz);  /securedObject type
     *    void decide(Authentication authentication, Object secureObject, Collection<ConfigAttribute> configAttributes)
     *                          throws AccessDeniedException, InsufficientAuthenticationException;
     *}
     *2)、AccessDecisionVoter<S> {
     *     int ACCESS_GRANTED = 1;
     * 	   int ACCESS_ABSTAIN = 0;
     * 	   int ACCESS_DENIED = -1;
     *
     * 	   boolean supports(ConfigAttribute attribute);
     * 	   boolean supports(Class<?> clazz);
     * 	   int vote(Authentication authentication, S object, Collection<ConfigAttribute> attributes);
     *}
     *
     *3、After-Invocation: 后置执行
     *1)、AfterInvocationManager {
     *      boolean supports(ConfigAttribute attribute);
     *      boolean supports(Class<?> clazz);
     *      Object decide(Authentication authentication, Object secureObject, Collection<ConfigAttribute> attributes, Object returnedObject)
     * 			throws AccessDeniedException;
     *}
     *
     *4、AbstractSecurityInterceptor 授权拦截器基类
     *public abstract class AbstractSecurityInterceptor {
     *      AccessDecisionManager accessDecisionManager;
     *      AfterInvocationManager afterInvocationManager;
     *      AuthenticationManager authenticationManager = new NoOpAuthenticationManager();
     *      RunAsManager runAsManager = new NullRunAsManager();
     *
     *      boolean alwaysReauthenticate = false;
     * 	    boolean rejectPublicInvocations = false;
     * 	    boolean validateConfigAttributes = true;   //验证ConfigAttribute是否被支持
     * 	    boolean publishAuthorizationSuccess = false;
     *
     *   protected InterceptorStatusToken beforeInvocation(Object object) {
     * 		Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);
     * 		if (attributes == null || attributes.isEmpty()) {
     * 			if (rejectPublicInvocations) {
     * 				throw new IllegalArgumentException(
     * 						"Secure object invocation "
     * 								+ object
     * 								+ " was denied as public invocations are not allowed via this interceptor. "
     * 								+ "This indicates a configuration error because the "
     * 								+ "rejectPublicInvocations property is set to 'true'");
     *            }
     *            publishEvent(new PublicInvocationEvent(object));
     * 			  return null; // no further work post-invocation
     *      }
     *      //从当前线程获取Authentication
     * 		if (SecurityContextHolder.getContext().getAuthentication() == null) {
     * 			throw AuthenticationCredentialsNotFoundException
     *      }
     *      //TODO,从当前线程获取Authentication,如果没有认证，使用authenticationManager走认证
     * 		Authentication authenticated = authenticateIfRequired();
     *
     * 		//Attempt authorize
     * 		try {
     * 			this.accessDecisionManager.decide(authenticated, object, attributes);
     *      } catch (AccessDeniedException accessDeniedException) {
     * 			publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated, accessDeniedException));
     * 			throw accessDeniedException;
     *      }
     * 		if (publishAuthorizationSuccess) {
     * 			publishEvent(new AuthorizedEvent(object, attributes, authenticated));
     *      }
     * 		// Attempt to run as a different user
     * 		Authentication runAs = this.runAsManager.buildRunAs(authenticated, object, attributes);
     *      //TODO,?Run-As
     * 		if (runAs == null) {
     * 			// no further work post-invocation
     * 			return new InterceptorStatusToken(SecurityContextHolder.getContext(), false, attributes, object);
     *      } else {
     * 			SecurityContext origCtx = SecurityContextHolder.getContext();
     * 			SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
     * 			SecurityContextHolder.getContext().setAuthentication(runAs);
     *
     * 			// need to revert to token.Authenticated post-invocation
     * 			return new InterceptorStatusToken(origCtx, true, attributes, object);
     *      }
     *   }
     *
     *   protected Object afterInvocation(InterceptorStatusToken token, Object returnedObject) {
     * 		if (token == null) {
     * 			return returnedObject;
     *      }
     * 		finallyInvocation(token); // continue to clean in this method for passivity
     * 		if (afterInvocationManager != null) {
     * 			// Attempt after invocation handling
     * 			try {
     * 				returnedObject = afterInvocationManager.decide(token.getSecurityContext()
     * 						.getAuthentication(), token.getSecureObject(), token
     * 						.getAttributes(), returnedObject);
     *          } catch (AccessDeniedException accessDeniedException) {
     * 				AuthorizationFailureEvent event = new AuthorizationFailureEvent(token.getSecureObject(), token.getAttributes(), token.getSecurityContext().getAuthentication(),accessDeniedException);
     * 				publishEvent(event);
     * 				throw accessDeniedException;
     *          }
     *      }
     * 		return returnedObject;
     * 	 }
     *
     *   protected void finallyInvocation(InterceptorStatusToken token) {
     * 		if (token != null && token.isContextHolderRefreshRequired()) {
     * 			SecurityContextHolder.setContext(token.getSecurityContext());
     * 		}
     *   }
     *}
     *
     *Filter形式
     *  实现Filter接口，并且配置在chain中
     *FilterSecurityInterceptor {
     *     FilterInvocationSecurityMetadataSource securityMetadataSource;
     *
     *     public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
     * 		   FilterInvocation fi = new FilterInvocation(request, response, chain);
     * 		   invoke(fi);
     *     }
     *     public void invoke(FilterInvocation fi) throws IOException, ServletException {
     * 		  if ((fi.getRequest() != null) && (fi.getRequest().getAttribute(FILTER_APPLIED) != null) && observeOncePerRequest) {
     * 			  fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
     *        } else {
     * 			if (fi.getRequest() != null && observeOncePerRequest)  fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
     *
     *          //传递FilterInvocation；前置执行
     * 			InterceptorStatusToken token = super.beforeInvocation(fi);
     * 			try {
     * 				fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
     *          } finally {
     *              //传递InterceptorStatusToken
     * 				super.finallyInvocation(token);
     *          }
     *          //传递InterceptorStatusToken，null；后置执行
     * 			super.afterInvocation(token, null);
     *        }
     *    }
     *}
     *配置access expression
     *.antMatchers("/", "/index").permitAll()
     *.antMatchers("/common/**").hasAuthority("common")
     *.anyRequest().authenticated()
     *or 通过 注解配置
     *
     *
     *
     *
     *第十三: HttpSession对象共享
     * @see FlSessionSample
     *
     *
     *
     *
     *
     */



}
