package com.freshjuice.poner.security;

public class FlSecurityOAuth2LoginSample {

    /**
     *作为Client访问其他OAuth2 provider,并在后端login(即,第三方OAuth2登录)
     *依赖
     * spring-boot-starter-security
     *  spring-security-web
     *    spring-security-core
     *  spring-security-config
     *    spring-security-core
     *
     *  spring-security-oauth2-client
     *    oauth2-oidc-sdk
     *    spring-security-core
     *    spring-security-web
     *    spring-security-oauth2-core
     *
     * 1、配置类 {@link com.freshjuice.poner.config.FlOAuth2LoginConfig}
     *
     * 2、执行流程
     *    a、前端请求 /oauth2/authorization/github
     *    b、OAuth2AuthorizationRequestRedirectFilter处理该请求，返回一个redirect
     *    c、前端处理redirect，重定向到OAuth2 provider的授权页面
     *    d、授权后,OAuth2 provider返回一个redirect，携带code&state参数
     *    e、OAuth2LoginAuthenticationFilter处理携带code的redirect请求，执行AuthenticationManager认证
     * github会记录client_id->code,client_id->token，如果使用client-id重定向到OAuth2 provider的授权页面且token已生成并且有效不会显示授权页面直接返回一个redirect，携带code&state参数
     *
     *
     * 2、OAuth2AuthorizationRequestRedirectFilter {
     *      //TODO,使用默认值即可，可覆盖
     *      public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
     * 	    private final ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
     * 	    //默认实现: Response.redirect
     * 	    private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
     * 	    //TODO,默认DefaultOAuth2AuthorizationRequestResolver，OAuth2AuthorizationRequest解析器
     * 	    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
     * 	    //TODO,默认实现依赖Session,需要重写
     * 	    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
     * 	    //禁用RequestCache后是NullRequestCache
     * 	    private RequestCache requestCache = new HttpSessionRequestCache();
     *
     *
     *    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
     * 			throws ServletException, IOException {
     *
     * 		try {
     * 	        //TODO,使用AuthorizationRequestResolver解析OAuth2AuthorizationRequest
     * 			OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
     * 			if (authorizationRequest != null) {
     * 		        //TODO,redirect
     * 				this.sendRedirectForAuthorization(request, response, authorizationRequest);
     * 				return;
     *          }
     *      } catch (Exception failed) {
     *          //TODO？此error会返回一个页面还是什么？？？？？
     * 			this.unsuccessfulRedirectForAuthorization(request, response, failed);
     * 			return;
     *      }
     *
     * 		try {
     * 			filterChain.doFilter(request, response);
     *      } catch (IOException ex) {
     * 			throw ex;
     *      } catch (Exception ex) {
     * 			// Check to see if we need to handle ClientAuthorizationRequiredException
     * 			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
     * 			ClientAuthorizationRequiredException authzEx = (ClientAuthorizationRequiredException) this.throwableAnalyzer.getFirstThrowableOfType(ClientAuthorizationRequiredException.class, causeChain);
     * 			if (authzEx != null) {
     * 				try {
     * 					OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request, authzEx.getClientRegistrationId());
     * 					if (authorizationRequest == null) {
     * 						throw authzEx;
     *                  }
     * 					this.sendRedirectForAuthorization(request, response, authorizationRequest);
     * 					this.requestCache.saveRequest(request, response);
     *              } catch (Exception failed) {
     * 					this.unsuccessfulRedirectForAuthorization(request, response, failed);
     *              }
     * 				return;
     *          }
     *
     * 			if (ex instanceof ServletException) {
     * 				throw (ServletException) ex;
     *          } else if (ex instanceof RuntimeException) {
     * 				throw (RuntimeException) ex;
     *          } else {
     * 				throw new RuntimeException(ex);
     *          }
     *        }
     *    }
     *
     *    private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
     * 												OAuth2AuthorizationRequest authorizationRequest) throws IOException, ServletException {
     *
     * 		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
     * 		    //TODO,授权码模式，则使用authorizationRequestRepository保存OAuth2AuthorizationRequest
     * 			this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
     *      }
     *      //TODO,redirect
     * 		this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());* 	}
     *
     * }
     *
     *
     * 3、OAuth2LoginAuthenticationFilter {
     *      AuthenticationManager authenticationManager;
     *      //Null remember-me
     *      RememberMeServices rememberMeServices = new NullRememberMeServices();
     *      //Null session-management
     *      SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();
     *      AuthenticationSuccessHandler successHandler
     *      AuthenticationFailureHandler failureHandler
     *      //TODO,默认拦截的路径: OAuth2 provider返回code的默认重定向地址
     *      public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";
     *      RequestMatcher requiresAuthenticationRequestMatcher;
     *      //TODO,ClientRegistrationRepository
     *      ClientRegistrationRepository clientRegistrationRepository;
     *      //TODO,OAuth2AuthorizedClientRepository
     *      OAuth2AuthorizedClientRepository authorizedClientRepository;
     *      //TODO,AuthorizationRequestRepository
     *      AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
     *
     *   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
     * 			throws AuthenticationException, IOException, ServletException {
     *
     *      //TODO，Request中的参数解析，如果没有code=...&state=...或者code=...&error=...表示参数有误，返回异常
     * 		MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
     * 		if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
     * 			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
     * 			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
     *      }
     *      //TODO，根据AuthorizationRequestRepository移除并获取OAuth2AuthorizationRequest
     * 		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
     * 		if (authorizationRequest == null) {
     * 			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
     * 			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
     *      }
     *      //TODO，获得RegistrationId,使用ClientRegistrationRepository获取ClientRegistration
     * 		String registrationId = (String) authorizationRequest.getAdditionalParameters().get(OAuth2ParameterNames.REGISTRATION_ID);
     * 		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
     * 		if (clientRegistration == null) {
     * 			OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE, "Client Registration not found with Id: " + registrationId, null);
     * 			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
     *      }
     *      //TODO，解析当前Request路径(即返回code的重定向地址)，创建OAuth2AuthorizationResponse
     * 		String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).replaceQuery(null).build().toUriString();
     * 		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params, redirectUri);
     *
     *      //TODO,构造OAuth2LoginAuthenticationToken
     * 		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
     * 		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
     *      //TODO,使用AuthenticationManager执行认证
     * 		OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) this.getAuthenticationManager().authenticate(authenticationRequest);
     *
     *      //TODO,构造OAuth2AuthenticationToken
     * 		OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
     * 			authenticationResult.getPrincipal(),
     * 			authenticationResult.getAuthorities(),
     * 			authenticationResult.getClientRegistration().getRegistrationId());
     *
     *      //TODO,构造并持久化OAuth2AuthorizedClient
     * 		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
     * 			authenticationResult.getClientRegistration(),
     * 			oauth2Authentication.getName(),
     * 			authenticationResult.getAccessToken(),
     * 			authenticationResult.getRefreshToken());
     * 		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
     *
     *      //TODO,返回OAuth2AuthenticationToken
     * 		return oauth2Authentication;
     * 	  }
     *
     * }
     *
     *
     *
     */

}
