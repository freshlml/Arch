package com.freshjuice.auth.security;

public class FlSecurityAuthSample {

    /**
     *spring security + OAuth2 的 authorization-server
     *
     */

    /**
     *spring-security-oauth2-authorization-server 实验性的
     *
     *spring-security-oauth2-authorization-server
     *  nimbus-jose-jwt
     *  spring-security-oauth2-jose
     *  spring-security-config
     *  spring-security-web
     *  spring-security-oauth2-core
     *  spring-security-oauth2-resource-server
     *
     *
     * @see com.freshjuice.auth.config.FlOAuth2AuthConfig TODO
     *
     */

    /**
     *spring-security-oauth2 将来会交给社区维护的
     *第一: 配置AuthorizationServer
     * @EnableAuthorizationServer {@link com.freshjuice.auth.config.FlOAuth2AuthorizationServerConfig}
     *
     * AuthorizationServer用到的组件配置 {@link com.freshjuice.auth.config.FlOAuth2AuthorizationComponentConfig}
     *
     *第二: 与spring security的关系
     * 1、AuthorizationServerSecurityConfiguration
     *  //认证服务的spring security相关配置，继承自 WebSecurityConfigurerAdapter
     *  public class AuthorizationServerSecurityConfiguration extends WebSecurityConfigurerAdapter {
     *      //TODO，保存AuthorizationServerConfigurer的list, eg: 自定义的FlOAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter
     *      @Autowired
     *      private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();
     *      //TODO,注入ClientDetailsService
     *      @Autowired
     *      private ClientDetailsService clientDetailsService;
     *      //TODO,注入AuthorizationServerEndpointsConfiguration
     *      @Autowired
     *      private AuthorizationServerEndpointsConfiguration endpoints;
     *
     *      @Autowired
     *      public void configure(ClientDetailsServiceConfigurer clientDetails) throws Exception {
     * 		    for (AuthorizationServerConfigurer configurer : configurers) {
     * 		        //TODO,对每一个AuthorizationServerConfigurer，调用 configure(ClientDetailsServiceConfigurer)
     * 			    configurer.configure(clientDetails);
     *          }
     *      }
     *      @Override
     *      protected void configure(HttpSecurity http) throws Exception {
     *          //TODO,构造AuthorizationServerSecurityConfigurer
     * 		    AuthorizationServerSecurityConfigurer configurer = new AuthorizationServerSecurityConfigurer();
     * 		    FrameworkEndpointHandlerMapping handlerMapping = endpoints.oauth2EndpointHandlerMapping();
     * 		    http.setSharedObject(FrameworkEndpointHandlerMapping.class, handlerMapping);
     * 		    configure(configurer);
     * 		    http.apply(configurer);
     * 		    String tokenEndpointPath = handlerMapping.getServletPath("/oauth/token");
     * 		    String tokenKeyPath = handlerMapping.getServletPath("/oauth/token_key");
     * 		    String checkTokenPath = handlerMapping.getServletPath("/oauth/check_token");
     * 		    if (!endpoints.getEndpointsConfigurer().isUserDetailsServiceOverride()) {
     * 			    UserDetailsService userDetailsService = http.getSharedObject(UserDetailsService.class);
     * 			    endpoints.getEndpointsConfigurer().userDetailsService(userDetailsService);
     *          }
     * 		    http
     *         	    .authorizeRequests()
     *             	.antMatchers(tokenEndpointPath).fullyAuthenticated()
     *             	.antMatchers(tokenKeyPath).access(configurer.getTokenKeyAccess())
     *             	.antMatchers(checkTokenPath).access(configurer.getCheckTokenAccess())
     *              .and()
     *         	    .requestMatchers()
     *             	.antMatchers(tokenEndpointPath, tokenKeyPath, checkTokenPath)
     *              .and()
     *         	    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
     *
     * 		        http.setSharedObject(ClientDetailsService.class, clientDetailsService);
     *      }
     * 	    protected void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
     * 		    for (AuthorizationServerConfigurer configurer : configurers) {
     * 		        //TODO,对每一个AuthorizationServerConfigurer，调用 configure(AuthorizationServerSecurityConfigurer)
     * 			    configurer.configure(oauthServer);
     *          }
     *      }
     *  }
     *
     * 2、AuthorizationServerSecurityConfigurer {
     *      AuthenticationEntryPoint authenticationEntryPoint;                                //ExceptionTranslationFilter 的 AuthenticationEntryPoint
     *      AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();        //ExceptionTranslationFilter 的 AccessDeniedHandler
     *      PasswordEncoder passwordEncoder;                                                  //设置PasswordEncoder
     *      String realm = "oauth2/client";                                                   //realm
     *      boolean allowFormAuthenticationForClients = false;
     *      String tokenKeyAccess = "denyAll()";                          //tokenKey的权限配置
     *      String checkTokenAccess = "denyAll()";                        //checkToken的权限配置
     *      boolean sslOnly = false;
     *      List<Filter> tokenEndpointAuthenticationFilters = new ArrayList<Filter>();        //设置自定义拦截器
     *
     *      @Override
     *      public void init(HttpSecurity http) throws Exception {
     *          //TODO，设置ExceptionTranslationFilter的AuthenticationEntryPoint
     * 		    registerDefaultAuthenticationEntryPoint(http);
     * 		    if (passwordEncoder != null) {
     * 		        //TODO,创建ClientDetailsUserDetailsService implements UserDetailsService
     * 			    ClientDetailsUserDetailsService clientDetailsUserDetailsService = new ClientDetailsUserDetailsService(clientDetailsService());
     * 			    //TODO,设置PasswordEncoder
     * 			    clientDetailsUserDetailsService.setPasswordEncoder(passwordEncoder());
     * 			    //TODO,在AuthenticationMangerBuilder中设置UserDetailsService实现，这将设置DaoAuthenticationProvider
     * 			    http.getSharedObject(AuthenticationManagerBuilder.class)
     * 					    .userDetailsService(clientDetailsUserDetailsService)
     * 					    .passwordEncoder(passwordEncoder());  //设置PasswordEncoder作为shareObject
     *          } else {//TODO,在AuthenticationMangerBuilder中设置UserDetailsService实现，这将设置DaoAuthenticationProvider
     * 			    http.userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService()));
     *          }
     *          //TODO,开启httpBasic,禁用SecurityContext的持久化，禁用csrf
     * 		    http.securityContext().securityContextRepository(new NullSecurityContextRepository()).and().csrf().disable()
     * 				    .httpBasic().realmName(realm);
     * 		    if (sslOnly) {
     * 			    http.requiresChannel().anyRequest().requiresSecure();
     *          }
     *      }
     *
     *      @Override
     *      public void configure(HttpSecurity http) throws Exception {
     * 		    frameworkEndpointHandlerMapping();
     * 		    //TODO,注册ClientCredentialsTokenEndpointFilter: 获取client_id,client_secret，使用DaoAuthenticationProvider执行认证，认证成功后将client_id封装在Authentication中
     * 		    if (allowFormAuthenticationForClients) {
     * 			    clientCredentialsTokenEndpointFilter(http);
     *          }
     * 		    for (Filter filter : tokenEndpointAuthenticationFilters) {
     * 			    http.addFilterBefore(filter, BasicAuthenticationFilter.class);
     *          }
     *          //TODO，设置ExceptionTranslationFilter 的 AccessDeniedHandler
     * 		    http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
     *    }
     * }
     *
     * 3、问题
     * TODO?问题: 1、目前没找到办法重定义HttpSecurity的内容，eg: 禁用HttpBasic、Logout、禁用SessionManager、禁用RequestCache
     *            2、设置给ExceptionTranslationFilter的AccessDeniedHandler不能成功
     *            3、没办法设置ExceptionTranslationFilter的RequestCache，而默认实现是HttpSessionRequestCache
     *
     * 4、AuthAuthenticationFilter
     *   1)、执行spring security的认证，生成OAuth2Authentication
     *   2)、使用自定义的拦截器，创建Authentication，封装client_id，用于替代ClientCredentialsTokenEndpointFilter和BasicAuthenticationFilter的认证逻辑，同时也可解决 问题3
     *
     * 5、自定义Config extends WebSecurityConfigurerAdapter
     *   1)、不在上述filter chain，是一条新的filter chain
     *   2)、拦截除了上述filter chain的其他请求
     *   3)、/oauth/authorize 请求需要认证，通过 /oauth/token认证，认证返回token，在携带token访问 /oauth/authorize，进入AuthAuthorizeFilter，根据token拿到userAuthentication
     *   4)、配置类 {@link com.freshjuice.auth.config.FlOAuth2SecurityConfig}
     *   5)、logout, 设置 {@link com.freshjuice.auth.security.logout.AuthTokenLogoutHandler} 用于删除TokenStore中存储的access_token、refresh_token、Authentication
     *   6)、同一个账户
     *     a)、直接请求/oauth/token
     *        client_credentials模式: client_id=for_client_credentials&scope=oauth2_user_client     无需认证(没有认证信息)                              client_id and scope                         权限较小，仅仅用作测验
     *        password模式和自定义模式: client_id=for_own&scope=all                                    使用AuthenticationManager认证，认证后统一的username username client_id and scope                本应用的自家前端使用，他们的token一致的(先后调用这两个接口就可以看到)
     *     b)、/oauth/authorize
     *        implicit模式和authorization_code模式: client_id=for_other&scope=oauth2_user             使用AuthenticationManager认证，认证后的username和password模式一致   username client_id and scope 给第三方应用使用，对于同一个账户(username)此处生成的token和password模式的token可以完全区分开
     *
     *
     *
     *第三: AuthorizationServer配置
     *
     * 1、认证服务配置
     *  public class AuthorizationServerEndpointsConfiguration {
     *      //TODO，认证服务组件配置类
     *      private AuthorizationServerEndpointsConfigurer endpoints = new AuthorizationServerEndpointsConfigurer();
     *      //TODO，注入ClientDetailsService
     *      @Autowired
     *      private ClientDetailsService clientDetailsService;
     *      //TODO，保存AuthorizationServerConfigurer的list, eg: 自定义的FlOAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter
     *      @Autowired
     *      private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();
     *
     *    //TODO:1、回调endpoints，用于在自定义的配置类中自定义认证服务组件
     *      @PostConstruct
     *      public void init() {
     * 		    for (AuthorizationServerConfigurer configurer : configurers) {
     * 			    try {
     * 			        //TODO，对每一个AuthorizationServerConfigurer，调用 configure(AuthorizationServerEndpointsConfigurer) 方法
     * 				    configurer.configure(endpoints);
     *              } catch (Exception e) {
     * 				    throw new IllegalStateException("Cannot configure enpdoints", e);
     *              }
     *          }
     *          //TODO,AuthorizationServerEndpointsConfigurer设置 ClientDetailsService
     * 		    endpoints.setClientDetailsService(clientDetailsService);
     *      }
     *
     *    //TODO:2、定义认证服务的endpoints
     *      //AuthorizationEndpoint: @RequestMapping(value = "/oauth/authorize")
     *      @Bean
     *      public AuthorizationEndpoint authorizationEndpoint() throws Exception {
     * 		    AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
     * 		    FrameworkEndpointHandlerMapping mapping = getEndpointsConfigurer().getFrameworkEndpointHandlerMapping();
     * 		    authorizationEndpoint.setUserApprovalPage(extractPath(mapping, "/oauth/confirm_access"));
     * 		    authorizationEndpoint.setProviderExceptionHandler(exceptionTranslator());
     * 		    authorizationEndpoint.setErrorPage(extractPath(mapping, "/oauth/error"));
     * 		    authorizationEndpoint.setTokenGranter(tokenGranter());
     * 		    authorizationEndpoint.setClientDetailsService(clientDetailsService);
     * 		    authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices());
     * 		    authorizationEndpoint.setOAuth2RequestFactory(oauth2RequestFactory());
     * 		    authorizationEndpoint.setOAuth2RequestValidator(oauth2RequestValidator());
     * 		    authorizationEndpoint.setUserApprovalHandler(userApprovalHandler());
     * 		    authorizationEndpoint.setRedirectResolver(redirectResolver());
     * 		    return authorizationEndpoint;
     *      }
     *      //WhitelabelApprovalEndpoint: @RequestMapping("/oauth/confirm_access")
     *      @Bean
     *      public WhitelabelApprovalEndpoint whitelabelApprovalEndpoint() {
     * 		    return new WhitelabelApprovalEndpoint();
     *      }
     *      //WhitelabelErrorEndpoint: @RequestMapping("/oauth/error")
     *      @Bean
     *      public WhitelabelErrorEndpoint whitelabelErrorEndpoint() {
     * 		    return new WhitelabelErrorEndpoint();
     *      }
     *
     *      //TokenEndpoint: @RequestMapping(value = "/oauth/token")
     *      @Bean
     *      public TokenEndpoint tokenEndpoint() throws Exception {
     * 		    TokenEndpoint tokenEndpoint = new TokenEndpoint();
     * 		    tokenEndpoint.setClientDetailsService(clientDetailsService);
     * 		    tokenEndpoint.setProviderExceptionHandler(exceptionTranslator());
     * 		    tokenEndpoint.setTokenGranter(tokenGranter());
     * 		    tokenEndpoint.setOAuth2RequestFactory(oauth2RequestFactory());
     * 		    tokenEndpoint.setOAuth2RequestValidator(oauth2RequestValidator());
     * 		    tokenEndpoint.setAllowedRequestMethods(allowedTokenEndpointRequestMethods());
     * 		    return tokenEndpoint;
     *      }
     *      //@RequestMapping(value = "/oauth/check_token")
     *      @Bean
     *      public CheckTokenEndpoint checkTokenEndpoint() {
     *          ...
     *      }
     *      //@RequestMapping(value = "/oauth/token_key", method = RequestMethod.GET)
     *      ...
     *
     *  }
     * 2、AuthorizationServerEndpointsConfigurer
     *  //认证服务组件配置类
     *  public final class AuthorizationServerEndpointsConfigurer {
     *      AuthenticationManager authenticationManager;       //TODO,AuthenticationManager
     *      ClientDetailsService clientDetailsService;         //TODO,ClientDetailsService
     *
     *      TokenGranter tokenGranter;                         //TODO,TokenGranter
     *      WebResponseExceptionTranslator<OAuth2Exception> exceptionTranslator;  //TODO,默认实现 DefaultWebResponseExceptionTranslator
     *
     *      DefaultTokenServices defaultTokenServices;  //DefaultTokenServices
     *      boolean tokenServicesOverride = false;
     *      AuthorizationServerTokenServices tokenServices; //TODO,默认实现 DefaultTokenServices
     *      ConsumerTokenServices consumerTokenServices;     //TODO,默认实现 DefaultTokenServices
     *      ResourceServerTokenServices resourceTokenServices;  //TODO,默认实现 DefaultTokenServices
     *
     *
     *      TokenStore tokenStore;                              //TODO，InMemoryTokenStore、JwtTokenStore、JwkTokenStore、JdbcTokenStore、RedisTokenStore
     *      TokenEnhancer tokenEnhancer;                        //TODO，JwtAccessTokenConverter
     *      AccessTokenConverter accessTokenConverter;         //TODO，DefaultAccessTokenConverter、JwtAccessTokenConverter
     *      boolean approvalStoreDisabled;                     //TODO，默认false-不禁用approvalStore
     *      ApprovalStore approvalStore;                       //TODO，TokenApprovalStore
     *      UserApprovalHandler userApprovalHandler;           //TODO，ApprovalStoreUserApprovalHandler、DefaultUserApprovalHandler、TokenStoreUserApprovalHandler
     *
     *      OAuth2RequestFactory requestFactory;               //TODO,默认实现 DefaultOAuth2RequestFactory
     *      OAuth2RequestValidator requestValidator;           //TODO,默认实现 DefaultOAuth2RequestValidator
     *
     *      boolean userDetailsServiceOverride = false;
     *      boolean reuseRefreshToken = true;                 //DefaultTokenServices.setReuseRefreshToken
     *      UserDetailsService userDetailsService;             //TODO,用于设置在DefaultTokenServices，当refresh_token时使用
     *
     *      FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping;  //FrameworkEndpointHandlerMapping
     *      String prefix;                                   //FrameworkEndpointHandlerMapping的prefix
     *      Map<String, String> patternMap = new HashMap<String, String>(); //FrameworkEndpointHandlerMapping的Mappings
     *      Set<HttpMethod> allowedTokenEndpointRequestMethods = new HashSet<HttpMethod>(); //allowed HttpMethod,默认 HttpMethod.POST
     *      List<Object> interceptors = new ArrayList<Object>();  //FrameworkEndpointHandlerMapping的interceptors
     *
     *      AuthorizationCodeServices authorizationCodeServices;  //TODO,默认实现 InMemoryAuthorizationCodeServices
     *      RedirectResolver redirectResolver;                                   //TODO,默认实现 DefaultRedirectResolver
     *  }
     *
     *3、endpoints
     * 1)、AbstractEndpoint
     * @FrameworkEndpoint
     * public class AbstractEndpoint {
     *      //默认DefaultWebResponseExceptionTranslator
     *      private WebResponseExceptionTranslator<OAuth2Exception> providerExceptionHandler = new DefaultWebResponseExceptionTranslator();
     * 	    //TokenGranter
     * 	    private TokenGranter tokenGranter;
     * 	    //ClientDetailsService
     * 	    private ClientDetailsService clientDetailsService;
     *      //默认DefaultOAuth2RequestFactory
     * 	    private OAuth2RequestFactory oAuth2RequestFactory;
     * 	    //默认DefaultOAuth2RequestFactory
     * 	    private OAuth2RequestFactory defaultOAuth2RequestFactory;
     * }
     * 2)、TokenEndpoint
     * public class TokenEndpoint extends AbstractEndpoint {
     *      //默认DefaultOAuth2RequestValidator
     *      private OAuth2RequestValidator oAuth2RequestValidator = new DefaultOAuth2RequestValidator();
     *      //默认allow HttpMethod.POST
     *      private Set<HttpMethod> allowedRequestMethods = new HashSet<HttpMethod>(Arrays.asList(HttpMethod.POST));
     *
     *      @RequestMapping(value = "/oauth/token") {
     *          ...
     *          //TODO,使用TokenGranter器获取access_token
     *          OAuth2AccessToken token = getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);
     *          ...
     *      }
     * }
     * TODO? 返回的json串的格式和异常的格式修改问题
     * 3)、AuthorizationEndpoint
     * @FrameworkEndpoint
     * @SessionAttributes("authorizationRequest")  //TODO,会将Model中该属性存放到session中
     * public class AuthorizationEndpoint extends AbstractEndpoint {
     *      private AuthorizationCodeServices authorizationCodeServices = new InMemoryAuthorizationCodeServices();
     *      private RedirectResolver redirectResolver = new DefaultRedirectResolver();
     *      //TokenStoreUserApprovalHandler
     *      private UserApprovalHandler userApprovalHandler = new DefaultUserApprovalHandler();
     *      //TODO?
     *      private SessionAttributeStore sessionAttributeStore = new DefaultSessionAttributeStore();
     *      private OAuth2RequestValidator oauth2RequestValidator = new DefaultOAuth2RequestValidator();
     *      //确认授权跳转: to WhitelabelApprovalEndpoint
     *      private String userApprovalPage = "forward:/oauth/confirm_access";
     *      //错误跳转: to WhitelabelErrorEndpoint
     *      private String errorPage = "forward:/oauth/error";
     *
     *      //跳转授权页面或者直接返回授权
     *      @RequestMapping(value = "/oauth/authorize") {
     *          //TODO:userApproveHandler处理，@see ApprovalStoreApprovalHandler
     *          authorizationRequest = userApprovalHandler.checkForPreApproval(authorizationRequest, (Authentication) principal);
     * 			boolean approved = userApprovalHandler.isApproved(authorizationRequest, (Authentication) principal);
     * 			authorizationRequest.setApproved(approved);
     *
     *          if (authorizationRequest.isApproved()) {  //TODO，userApprove=true,直接返回，不跳转授权页面
     * 				if (responseTypes.contains("token")) return getImplicitGrantResponse(authorizationRequest);  //implicit模式，返回redirect_uri和token
     * 				if (responseTypes.contains("code")) return new ModelAndView(getAuthorizationCodeResponse(authorizationRequest, (Authentication) principal)); //authorization_code模式，返回redirect_uri和code
     * 			}
     *
     *          //TODO,Place auth request into the model so that it is stored in the session
     *          model.put("authorizationRequest", authorizationRequest);
     *
     *          //TODO,跳转确认授权: userApprovalPage
     *          return getUserApprovalPageResponse(model, authorizationRequest, (Authentication) principal);
     *      }
     *
     *      //带有user_oauth_approval参数: 确认授权
     *      @RequestMapping(value = "/oauth/authorize", method = RequestMethod.POST, params = OAuth2Utils.USER_OAUTH_APPROVAL) {
     *
     *          //之前保存在session中的
     *          AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
     *
     *          //@see ApprovalStoreUserApprovalHandler
     *          authorizationRequest = userApprovalHandler.updateAfterApproval(authorizationRequest, (Authentication) principal);
     *
     *          //implicit模式，返回redirect_uri和token， 使用ImplicitTokenGranter生成token
     *          if (responseTypes.contains("token")) return getImplicitGrantResponse(authorizationRequest).getView();
     * 			//authorization_code模式，返回redirect_uri和code, authorizationCodeServices将code-Authentication存储起来
     * 			return getAuthorizationCodeResponse(authorizationRequest, (Authentication) principal);
     *
     *          finally {
     *              sessionStatus.setComplete();
     *          }
     *      }
     * }
     *
     * 4)、WhitelabelApprovalEndpoint
     * @FrameworkEndpoint
     * @SessionAttributes("authorizationRequest")
     * public class WhitelabelApprovalEndpoint {
     *      @RequestMapping("/oauth/confirm_access") {
     *          返回授权页面
     *      }
     * }
     * 5)、WhitelabelErrorEndpoint
     * @FrameworkEndpoint
     * public class WhitelabelErrorEndpoint {
     *      @RequestMapping("/oauth/error") {
     *          返回错误页面
     *      }
     * }
     *
     *第四: OAuth2 认证组件
     *
     *1、ClientDetailsService
     * OAuth2认证中心保存的Client信息（or 客户端在OAuth2认证中心注册的Client信息）
     * public interface ClientDetailsService {
     *      ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException;
     * }
     * 定义基于mysql的实现类: {@link com.freshjuice.auth.security.clientdetails.DbClientDetailsService}
     *
     *
     *2、TokenGranter
     *  1)、TokenGranter
     *  public interface TokenGranter {
     * 	    OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest);
     *  }
     *  2)、AbstractTokenGranter
     *  public abstract class AbstractTokenGranter implements TokenGranter {
     *      //TODO，一般默认实现是 DefaultTokenServices
     *      private final AuthorizationServerTokenServices tokenServices;
     *      //ClientDetailsService
     *      private final ClientDetailsService clientDetailsService;
     *      private final OAuth2RequestFactory requestFactory;
     *      private final String grantType;
     *
     *      public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
     * 		      if (!this.grantType.equals(grantType)) return null;
     *            //TODO，使用ClientDetailsService获取ClientId
     * 		      String clientId = tokenRequest.getClientId();
     * 		      ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
     * 		      //TODO，校验grantType: ClientDetails支持的grant_type是否支持参数grantType
     * 		      validateGrantType(grantType, client);
     *            //TODO，创建token:1、执行认证;2、创建OAuth2AccessToken
     * 		      return getAccessToken(client, tokenRequest);
     *     	}
     *     	protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
     * 		      return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest));
     *      }
     *      protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
     * 		      OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(client, tokenRequest);
     * 		      return new OAuth2Authentication(storedOAuth2Request, null);
     *      }
     *  }
     *  3)、ClientCredentialsTokenGranter
     *  public class ClientCredentialsTokenGranter extends AbstractTokenGranter {
     *      //grant_type
     *      private static final String GRANT_TYPE = "client_credentials";
     *  	private boolean allowRefresh = false;
     *
     *      @Override
     *      public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
     * 		    //TODO,执行super.grant
     * 		    OAuth2AccessToken token = super.grant(grantType, tokenRequest);
     * 		    if (token != null) {
     * 			    DefaultOAuth2AccessToken norefresh = new DefaultOAuth2AccessToken(token);
     * 			    // The spec says that client credentials should not be allowed to get a refresh token
     * 			    if (!allowRefresh) norefresh.setRefreshToken(null);
     * 			    token = norefresh;
     *          }
     * 		    return token;
     *      }
     *  }
     *  4)、RefreshTokenGranter
     *      @Override
     *      protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
     * 		    String refreshToken = tokenRequest.getRequestParameters().get("refresh_token");
     * 		    //AuthorizationServerTokenServices.refreshAccessToken
     * 		    return getTokenServices().refreshAccessToken(refreshToken, tokenRequest);
     *      }
     *  5)、ResourceOwnerPasswordTokenGranter
     *      使用AuthenticationManager执行认证，DaoAuthenticationProvider
     *  6)、PhoneCodeTokenGranter
     *      使用AuthenticationManager执行认证，PhoneCodeAuthenticationProvider
     *  7)、AuthorizationCodeTokenGranter
     *      校验code参数，redirect_uri参数
     *      根据authorizationCodeServices获取Authentication(/oauth/authorize时已认证的Authentication)
     *
     *
     *3、AuthorizationServerTokenServices
     * public interface AuthorizationServerTokenServices {
     *      OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException;
     *      OAuth2AccessToken refreshAccessToken(String refreshToken, TokenRequest tokenRequest) throws AuthenticationException;
     *      OAuth2AccessToken getAccessToken(OAuth2Authentication authentication);
     * }
     * 默认实现类 DefaultTokenServices
     * public class DefaultTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices, ConsumerTokenServices {
     *      private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.
     * 	    private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.
     *      private boolean supportRefreshToken = false;
     * 	    private boolean reuseRefreshToken = true;
     * 	    //TokenStore
     * 	    private TokenStore tokenStore;
     * 	    //TokenEnhancer
     * 	    private TokenEnhancer accessTokenEnhancer;
     * 	    //ClientDetailsService
     *      private ClientDetailsService clientDetailsService;
     *      //独立的AuthenticationManager，用于refresh_token
     * 	    private AuthenticationManager authenticationManager;
     *
     *      @Transactional
     *      public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
     *          //TODO，已存在(username,client_id,scope) access_token逻辑
     * 		    OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
     * 		    OAuth2RefreshToken refreshToken = null;
     * 		    if (existingAccessToken != null) {
     * 			    if (existingAccessToken.isExpired()) {
     * 				    if (existingAccessToken.getRefreshToken() != null) {
     * 					    refreshToken = existingAccessToken.getRefreshToken();
     * 					    tokenStore.removeRefreshToken(refreshToken);
     *                  }
     * 				    tokenStore.removeAccessToken(existingAccessToken);
     *              } else {
     * 				    // Re-store the access token in case the authentication has changed
     * 				    tokenStore.storeAccessToken(existingAccessToken, authentication);
     * 				    return existingAccessToken;
     *              }
     *          }
     *
     *          //TODO,创建refresh_token, DefaultExpiringOAuth2RefreshToken or DefaultOAuth2RefreshToken, token的形式是UUID
     * 		    if (refreshToken == null) {
     * 			    refreshToken = createRefreshToken(authentication);
     *          } else if (refreshToken instanceof ExpiringOAuth2RefreshToken) { //当access_token存在并且已过期时，重复使用其refresh_token
     * 			    ExpiringOAuth2RefreshToken expiring = (ExpiringOAuth2RefreshToken) refreshToken;
     * 			    if (System.currentTimeMillis() > expiring.getExpiration().getTime()) {
     * 				    refreshToken = createRefreshToken(authentication);
     *              }
     *          }
     *          //TODO，创建access_token: DefaultOAuth2AccessToken,token的形式是UUID,使用TokenEnhancer enhance该token
     * 		    OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
     *
     * 		    //TODO,使用TokenStore存储 access_token,refresh_token
     * 		    tokenStore.storeAccessToken(accessToken, authentication);
     * 		    refreshToken = accessToken.getRefreshToken();
     * 		    if (refreshToken != null) {
     * 			    tokenStore.storeRefreshToken(refreshToken, authentication);
     *          }
     * 		    return accessToken;
     *    }
     *    @Transactional(noRollbackFor={InvalidTokenException.class, InvalidGrantException.class})
     * 	  public OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest tokenRequest) throws AuthenticationException {
     * 		    if (!supportRefreshToken) throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
     *
     *          //TODO,读取refresh_token
     * 		    OAuth2RefreshToken refreshToken = tokenStore.readRefreshToken(refreshTokenValue);
     * 		    if (refreshToken == null) throw new InvalidGrantException("Invalid refresh token: " + refreshTokenValue);
     *          //TODO，AuthenticationManager认证
     * 		    OAuth2Authentication authentication = tokenStore.readAuthenticationForRefreshToken(refreshToken);
     * 		    if (this.authenticationManager != null && !authentication.isClientOnly()) {
     * 			    Authentication user = new PreAuthenticatedAuthenticationToken(authentication.getUserAuthentication(), "", authentication.getAuthorities());
     * 			    user = authenticationManager.authenticate(user);
     * 			    Object details = authentication.getDetails();
     * 			    authentication = new OAuth2Authentication(authentication.getOAuth2Request(), user);
     * 			    authentication.setDetails(details);
     *          }
     * 		    String clientId = authentication.getOAuth2Request().getClientId();
     * 		    if (clientId == null || !clientId.equals(tokenRequest.getClientId())) throw new InvalidGrantException("Wrong client for this refresh token: " + refreshTokenValue);
     *
     * 		    // clear out any access tokens already associated with the refresh_token.
     * 		    tokenStore.removeAccessTokenUsingRefreshToken(refreshToken);
     *
     * 		    if (isExpired(refreshToken)) {//如果refresh_token过期了
     * 			    tokenStore.removeRefreshToken(refreshToken);
     * 			    throw new InvalidTokenException("Invalid refresh token (expired): " + refreshToken);
     *          }
     *
     * 		    authentication = createRefreshedAuthentication(authentication, tokenRequest);
     *
     * 		    if (!reuseRefreshToken) { //是否重复利用refresh_token
     * 			    tokenStore.removeRefreshToken(refreshToken);
     * 			    refreshToken = createRefreshToken(authentication);
     *          }
     *          //TODO，创建并保存access_token
     * 		    OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
     * 		    tokenStore.storeAccessToken(accessToken, authentication);
     * 		    if (!reuseRefreshToken) {
     * 			    tokenStore.storeRefreshToken(accessToken.getRefreshToken(), authentication);
     *          }
     * 		    return accessToken;
     * 	  }
     *
     *    public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
     * 		    return tokenStore.getAccessToken(authentication);
     *    }
     *
     *    //实现 ResourceServerTokenServices
     *    public OAuth2AccessToken readAccessToken(String accessToken) {
     * 		    return tokenStore.readAccessToken(accessToken);
     *    }
     *    public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException,InvalidTokenException {
     * 		    OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
     * 		    if (accessToken == null) throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
     * 		    else if (accessToken.isExpired()) {
     * 			    tokenStore.removeAccessToken(accessToken);
     * 			    throw new InvalidTokenException("Access token expired: " + accessTokenValue);
     *          }
     * 		    OAuth2Authentication result = tokenStore.readAuthentication(accessToken);
     * 		    if (result == null) {
     * 			    throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
     *          }
     * 		    if (clientDetailsService != null) {
     * 			    String clientId = result.getOAuth2Request().getClientId();
     * 			    try {
     * 				    clientDetailsService.loadClientByClientId(clientId);
     *              } catch (ClientRegistrationException e) {
     * 				    throw new InvalidTokenException("Client not valid: " + clientId, e);
     *              }
     *          }
     * 		    return result;
     * 	  }
     *
     *    //实现 ConsumerTokenServices
     *    public boolean revokeToken(String tokenValue) {
     * 		    OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenValue);
     * 		    if (accessToken == null) return false;
     * 		    if (accessToken.getRefreshToken() != null) {
     * 			    tokenStore.removeRefreshToken(accessToken.getRefreshToken());
     *          }
     * 		    tokenStore.removeAccessToken(accessToken);
     * 		    return true;
     * 	  }
     * }
     *
     *4、TokenStore
     * 1)、
     * public interface TokenStore {
     *      //TODO,1、store OAuth2AccessToken,OAuth2Authentication               ,eg: <access_token, OAuth2AccessToken>,<access_token, OAuthAuthentication>
     *      void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication);
     *      //TODO,1、根据access_token获取OAuth2AccessToken                        ,eg: <access_token, OAuth2AccessToken>
     *      OAuth2AccessToken readAccessToken(String tokenValue);
     *      //TODO,1、根据OAuth2AccessToken/access_token 获取OAuth2Authentication  ,eg: <access_token, OAuthAuthentication>
     *      OAuth2Authentication readAuthentication(OAuth2AccessToken token);
     *      OAuth2Authentication readAuthentication(String token);
     *      //TODO,1、remove
     *      void removeAccessToken(OAuth2AccessToken token);
     *
     *      //TODO,2、store OAuth2RefreshToken,OAuth2Authentication
     *      void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication);
     *      //TODO,2、根据refresh_token获取OAuth2RefreshToken
     *      OAuth2RefreshToken readRefreshToken(String tokenValue);
     *      //TODO,2、根据OAuth2RefreshToken 获取OAuth2Authentication
     *      OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token);
     *      //TODO,2、remove
     *      void removeRefreshToken(OAuth2RefreshToken token);
     *      void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken);
     *      //TODO,3、根据OAuth2Authentication 获取OAuth2AccessToken
     *      OAuth2AccessToken getAccessToken(OAuth2Authentication authentication);
     *      Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName);
     *      Collection<OAuth2AccessToken> findTokensByClientId(String clientId);
     * }
     * 2)、InMemoryTokenStore
     * store in memory
     * public class InMemoryTokenStore implements TokenStore {
     *      private static final int DEFAULT_FLUSH_INTERVAL = 1000;
     *      //TODO,<access_token, OAuth2AccessToken>
     *      private final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();
     *      //TODO,<auth_key, OAuth2AccessToken>
     *  	private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();
     *      //TODO,<username, OAuth2AccessToken> OAuth2Authentication.userAuthentication.getName()
     *      private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> userNameToAccessTokenStore = new ConcurrentHashMap<String, Collection<OAuth2AccessToken>>();
     *      //TODO,<clientId, OAuth2AccessToken>
     *      private final ConcurrentHashMap<String, Collection<OAuth2AccessToken>> clientIdToAccessTokenStore = new ConcurrentHashMap<String, Collection<OAuth2AccessToken>>();
     *
     *      //TODO,<refresh_token, OAuth2RefreshToken>
     *      private final ConcurrentHashMap<String, OAuth2RefreshToken> refreshTokenStore = new ConcurrentHashMap<String, OAuth2RefreshToken>();
     *
     *      //TODO,<access_token, refresh_token>
     *      private final ConcurrentHashMap<String, String> accessTokenToRefreshTokenStore = new ConcurrentHashMap<String, String>();
     *      //TODO,<refresh_token, access_token>
     *      private final ConcurrentHashMap<String, String> refreshTokenToAccessTokenStore = new ConcurrentHashMap<String, String>();
     *
     *      //TODO,<access_token, OAuth2Authentication>
     *      private final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap<String, OAuth2Authentication>();
     *      //TODO,<refresh_token, OAuth2Authentication>
     *      private final ConcurrentHashMap<String, OAuth2Authentication> refreshTokenAuthenticationStore = new ConcurrentHashMap<String, OAuth2Authentication>();
     *
     *      private final DelayQueue<TokenExpiry> expiryQueue = new DelayQueue<TokenExpiry>();
     *      private final ConcurrentHashMap<String, TokenExpiry> expiryMap = new ConcurrentHashMap<String, TokenExpiry>();
     *      private int flushInterval = DEFAULT_FLUSH_INTERVAL;
     *      private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
     *      private AtomicInteger flushCounter = new AtomicInteger(0);
     * }
     * 3)、JwtTokenStore、JwkTokenStore
     * read data from toke themselves,not really store
     * public class JwtTokenStore implements TokenStore {
     *      //JwtAccessTokenConverter 同时是TokenEnhancer
     *      private JwtAccessTokenConverter jwtTokenEnhancer;
     *      //默认，TokenApprovalStore
     * 	    private ApprovalStore approvalStore;
     * }
     * TODO?JwtAccessTokenConverter,JwkTokenStore
     * 4)、JdbcTokenStore
     *   store in table
     * 5)、RedisTokenStore
     *   store in redis
     *
     *5、ApproveStore, UserApprovalHandler
     * 1)、UserApprovalHandler
     * public interface UserApprovalHandler {
     *      //Tests whether the specified authorization request has been approved
     *      boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication);
     *      //Provides a hook for allowing requests to be pre-approved (skipping the User Approval Page),
     *      //Some implementations may allow users to store approval decisions so
     * 	    //that they only have to approve a site once
     *      AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication);
     *      AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication);
     *      Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest, Authentication userAuthentication);
     * }
     * 2)、ApprovalStoreUserApprovalHandler
     * public class ApprovalStoreUserApprovalHandler implements UserApprovalHandler, InitializingBean {
     *      private String scopePrefix = OAuth2Utils.SCOPE_PREFIX; //scope.
     *      private ApprovalStore approvalStore;      //TokenApprovalStore
     *      private int approvalExpirySeconds = -1;  //Approval过期时间
     *      private ClientDetailsService clientDetailsService;
     *      private OAuth2RequestFactory requestFactory;
     *
     *
     *      public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
     * 		    return authorizationRequest.isApproved();
     *      }
     *
     *      public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
     * 			Authentication userAuthentication) {
     *
     * 		    String clientId = authorizationRequest.getClientId();
     * 		    Collection<String> requestedScopes = authorizationRequest.getScope();
     * 		    Set<String> approvedScopes = new HashSet<String>();
     * 		    Set<String> validUserApprovedScopes = new HashSet<String>();
     *
     *          //TODO，ClientDetails中配置的autoApprove支持处理
     * 		    if (clientDetailsService != null) {
     * 			    try {
     * 				    ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
     * 				    for (String scope : requestedScopes) {
     * 					    if (client.isAutoApprove(scope)) {
     * 						    approvedScopes.add(scope);
     *                      }
     *                  }
     * 				    if (approvedScopes.containsAll(requestedScopes)) {
     * 					    Set<Approval> approvals = new HashSet<Approval>();
     * 					    Date expiry = computeExpiry();
     * 					    for (String approvedScope : approvedScopes) {
     * 						    approvals.add(new Approval(userAuthentication.getName(), authorizationRequest.getClientId(),
     * 								    approvedScope, expiry, ApprovalStatus.APPROVED));
     *                      }
     *                      //TODO,使用approvalStore存储Approval，@see TokenApprovalStore
     * 					    approvalStore.addApprovals(approvals);
     *
     * 					    authorizationRequest.setApproved(true);
     * 					    return authorizationRequest;
     *                  }
     *              } catch (ClientRegistrationException e) {
     * 				    logger.warn("Client registration problem prevent auto approval check for client=" + clientId);
     *              }
     *          }
     *
     *          //TODO,根据approvalStore获取Approval @see TokenApprovalStore,如果该clientId,和userAuthentication.getName()已经生成了token(eg: /oauth/token接口)将autoApprove=true
     *          Collection<Approval> userApprovals = approvalStore.getApprovals(userAuthentication.getName(), clientId);  //TODO,此userAuthentication 为AuthorizationEndpoint中认证过的Authentication
     * 		    Date today = new Date();
     * 		    for (Approval approval : userApprovals) {
     * 			    if (approval.getExpiresAt().after(today)) {
     * 				    if (approval.getStatus() == ApprovalStatus.APPROVED) {
     * 					    validUserApprovedScopes.add(approval.getScope());
     * 					    approvedScopes.add(approval.getScope());
     *                  }
     *              }
     *          }
     * 		    if (validUserApprovedScopes.containsAll(requestedScopes)) {
     * 			    approvedScopes.retainAll(requestedScopes);
     * 			    authorizationRequest.setScope(approvedScopes);
     * 			    authorizationRequest.setApproved(true);
     *          }
     *
     * 		    return authorizationRequest;
     * 	    }
     *
     * 	    //A scope that was requested in the authorization request can be approved by sending a request
     * 	    //parameter <code>scope.&lt;scopename&gt;</code> equal to "true" or "approved" (otherwise it will be assumed to
     * 	    //have been denied)
     * 	    public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
     * 			Authentication userAuthentication) {
     * 	        ...
     * 		}
     * }
     * 3)、ApprovalStore
     *  public interface ApprovalStore {
     * 	    public boolean addApprovals(Collection<Approval> approvals);
     * 	    public boolean revokeApprovals(Collection<Approval> approvals);
     * 	    public Collection<Approval> getApprovals(String userId, String clientId);
     * }
     * 4)、TokenApprovalStore
     * public class TokenApprovalStore implements ApprovalStore {
     *      private TokenStore store;
     *
     *      //TODO,不存储Approval
     *      public boolean addApprovals(Collection<Approval> approvals) {
     * 		    return true;
     *      }
     *      //TODO,find Authentication
     *      public Collection<Approval> getApprovals(String userId, String clientId) {
     *          Collection<Approval> result = new HashSet<Approval>();
     *          //TokenStore中根据clientId,username获取是否存在access_token, eg: 调用/oauth/token接口获取token后
     * 		    Collection<OAuth2AccessToken> tokens = store.findTokensByClientIdAndUserName(clientId, userId);
     * 		    for (OAuth2AccessToken token : tokens) {
     * 			    OAuth2Authentication authentication = store.readAuthentication(token);
     * 			    if (authentication != null) {
     * 				    Date expiresAt = token.getExpiration();
     * 				    for (String scope : token.getScope()) {
     * 					    result.add(new Approval(userId, clientId, scope, expiresAt, ApprovalStatus.APPROVED));
     *                  }
     *              }
     *          }
     * 		    return result;
     *      }
     * }
     *
     *
     *
     *
     *推演:
     *   1)、client_credentials模式
     *      /oauth/token
     *      body参数: grant_type=client_credentials&client_id=for_client_credentials&client_secret=secret&scope=scope
     *      说明: client_credentials模式校验client_id和client_secret(验证请求的Client的合法性)
     *           AuthAuthenticationFilter中校验验证码client_id,client_secret
     *           由于没有进行用户相关的任何校验，所有该ClientCredentials配置时的资源权限应该很低
     *
     *   2)、password模式
     *      /oauth/token
     *      body参数: grant_type=password&client_id=id&client_secret=secret&username=name&password=pwd&scope=scope
     *      说明: AuthAuthenticationFilter中可以校验验证码
     *           ResourceOwnerPasswordTokenGranter中校验username,password
     *           支持刷新token: body参数: grant_type=refresh_token&client_id=id&client_secret=secret&refresh_token=refresh_token&scope=scope
     *
     *   3)、自定义模式
     *      /oauth/token
     *      body参数: grant_type=phone_code&client_id=id&client_secret=secret&phone=15623236821&sms_code=123456&scope=scope
     *      说明: PhoneCodeTokenGranter
     *           支持刷新token: body参数: grant_type=refresh_token&client_id=id&client_secret=secret&refresh_token=refresh_token&scope=scope
     *
     *   4)、Implicit模式
     *      /oauth/authorize response_type=token&client_id=for_other&redirect_uri=url&state=state&scope=scope
     *      or body参数: response_type=token&client_id=id&redirect_uri=url&state=state&scope=scope
     *      授权页面确认授权: /oauth/authorize
     *                   body参数: user_oauth_approval=true&scope.oauth2_user=true&authorize=true
     *              授权页面确认授权后redirect: redirect_uri?token=token&state=state
     *
     *   5)、Authorization_code模式
     *      /oauth/authorize response_type=code&client_id=for_other&redirect_uri=url&state=state&scope=scope
     *      授权页面确认授权: /oauth/authorize
     *                    body参数: user_oauth_approval=true&scope.oauth2_user=true&authorize=true
     *                授权页面确认授权后redirect: redirect_uri?code=sNTqLd&state=state
     *
     *      /oauth/token
     *      body参数: grant_type=authorization_code&code=code&client_id=for_other&client_secret=secret&redirect_uri=之前的url&scope=scope
     *
     *
     *      交互流程Web原始:
     *      1、第三方Client(Web)请求授权: /oauth/authorize
     *      2、如果携带token，userApproval判断为true执行redirect，进行6，否则返回授权页面，进行5
     *      3、如果不携带token，返回登录页面，进行4
     *      4、第三方Client显示登录页面，确认登录接口: /oauth/token,返回token，进行2
     *      5、授权页面确认授权: /oauth/authorize,执行redirect
     *      6、第三方Client调用/oauth/token获取token，get_user等形式接口获取若干用户信息
     *
     *      交互流程Web原始2:
     *      1、第三方Client(Web)请求授权: /oauth/authorize
     *      2、不管是否携带token，返回登录并授权页面，第三方Client浏览器显示该页面
     *      3、登录授权页面确认: /oauth/authorize，携带登录信息和授权参数, 执行redirect
     *      4、第三方Client调用 /oauth/token获取token，get_user等形式接口获取若干用户信息
     *
     *      交互流程Web:
     *      1、第三方Client(Web)跳转我方Web应用的一个地址，我方Web应用请求授权: /oauth/authorize
     *      2、如果携带token，userApproval判断为true执行redirect，进行6，否则返回授权json数据，进行5
     *      3、如果不携带token，返回未登录json数据，进行4
     *      4、我方Web应用跳转登录页面，确认登录接口: /oauth/token,返回token，进行2    TODO? 前端浏览器有盗用token的问题
     *      5、跳转授权页面，授权页面确认授权: /oauth/authorize,执行redirect
     *      6、第三方Client调用/oauth/token获取token，get_user等形式接口获取若干用户信息
     *
     *      交互流程Web2:
     *      1、第三方Client(Web)跳转我方Web应用的一个地址，我方Web应用请求授权: /oauth/authorize
     *      2、不管是否携带token，返回未登录json数据，我方Web应用跳转登录授权页面            TODO? 没有了userApproval逻辑
     *      3、登录授权页面确认: /oauth/authorize，携带登录信息和授权参数, 执行redirect
     *      4、第三方Client调用/oauth/token获取token，get_user等形式接口获取若干用户信息
     *
     *
     *      交互流程App:
     *      1、第三方Client(App)调起我方App，我方App请求授权: /oauth/authorize
     *      2、如果携带token，userApproval判断为true返回授权成功，进行6，否则返回授权json数据，进行5
     *      3、如果不携带token，返回未登录json数据，进行4
     *      4、我方App跳转登录页面，确认登录接口: /oauth/token,返回token，进行2
     *      5、跳转授权页面，授权页面确认授权: /oauth/authorize,返回授权成功(App流程无需redirect)
     *      6、第三方Client调用/oauth/token获取token，get_user等形式接口获取若干用户信息
     *
     *      TODO??,交互流程还需验证，涉及的诸多组件也需要重写
     *
     *
     */



}
