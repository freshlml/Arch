package com.freshjuice.poner.security;

public class FlSecurityOAuth2ClientSample {

    /**
     *作为Client访问其他OAuth2 provider
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
     * 配置类: {@link com.freshjuice.poner.config.FlOAuth2ClientConfig}
     *
     * OAuth2AuthorizationRequestRedirectFilter,
     * @see FlSecurityOAuth2LoginSample
     *
     *
     * OAuth2AuthorizationCodeGrantFilter
     * public class OAuth2AuthorizationCodeGrantFilter
     *
     *      private final ClientRegistrationRepository clientRegistrationRepository;
     * 	    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
     * 	    private final AuthenticationManager authenticationManager;
     * 	    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
     * 	    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
     * 	    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
     * 	    private RequestCache requestCache = new HttpSessionRequestCache();
     *
     *      @Override
     *      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
     * 		    if (matchesAuthorizationResponse(request)) {
     * 			    processAuthorizationResponse(request, response);
     * 			    return;
     *          }
     * 		    filterChain.doFilter(request, response);
     *      }
     *      private boolean matchesAuthorizationResponse(HttpServletRequest request) {
     *          //TODO，Request中的参数解析，如果没有code=...&state=...或者code=...&error=...表示参数有误，返回false
     * 		    MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
     * 		    if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) return false;
     *
     * 		    //TODO，根据AuthorizationRequestRepository获取OAuth2AuthorizationRequest
     * 		    OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.loadAuthorizationRequest(request);
     * 		    if (authorizationRequest == null) return false;
     *
     * 		    // Compare redirect_uri
     * 		    UriComponents requestUri = UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request)).build();
     * 		    UriComponents redirectUri = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri()).build();
     * 		    Set<Map.Entry<String, List<String>>> requestUriParameters = new LinkedHashSet<>(requestUri.getQueryParams().entrySet());
     * 		    Set<Map.Entry<String, List<String>>> redirectUriParameters = new LinkedHashSet<>(redirectUri.getQueryParams().entrySet());
     * 		    // Remove the additional request parameters (if any) from the authorization
     * 		    // response (request)
     * 		    // before doing an exact comparison with the authorizationRequest.getRedirectUri()
     * 		    // parameters (if any)
     * 		    requestUriParameters.retainAll(redirectUriParameters);
     * 		    if (Objects.equals(requestUri.getScheme(), redirectUri.getScheme())
     * 				&& Objects.equals(requestUri.getUserInfo(), redirectUri.getUserInfo())
     * 				&& Objects.equals(requestUri.getHost(), redirectUri.getHost())
     * 				&& Objects.equals(requestUri.getPort(), redirectUri.getPort())
     * 				&& Objects.equals(requestUri.getPath(), redirectUri.getPath())
     * 				&& Objects.equals(requestUriParameters.toString(), redirectUriParameters.toString())) {
     * 			    return true;
     *          }
     * 		    return false;
     * 	    }
     *
     *      private void processAuthorizationResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
     * 		    //TODO，根据AuthorizationRequestRepository移除并获取OAuth2AuthorizationRequest
     * 		    OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
     * 		    //TODO，获得RegistrationId,使用ClientRegistrationRepository获取ClientRegistration
     * 		    String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
     * 		    ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
     *
     * 		    MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
     * 		    String redirectUri = UrlUtils.buildFullRequestUrl(request);
     * 		    OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params, redirectUri);
     * 		    //TODO，构造OAuth2AuthorizationCodeAuthenticationToken，使用AuthenticationManager执行认证
     * 		    OAuth2AuthorizationCodeAuthenticationToken authenticationRequest = new OAuth2AuthorizationCodeAuthenticationToken(clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
     * 		    authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
     * 		    OAuth2AuthorizationCodeAuthenticationToken authenticationResult;
     * 		    try {
     * 			    authenticationResult = (OAuth2AuthorizationCodeAuthenticationToken) this.authenticationManager.authenticate(authenticationRequest);
     *          } catch (OAuth2AuthorizationException ex) {
     * 			    OAuth2Error error = ex.getError();
     * 			    UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(authorizationRequest.getRedirectUri()).queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
     * 			    if (!StringUtils.isEmpty(error.getDescription())) {
     * 				    uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
     *              }
     * 			    if (!StringUtils.isEmpty(error.getUri())) {
     * 				    uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
     *              }
     *              //TODO,redirect，redirect地址为ClientRegistration中配置的redirectUri
     * 			    this.redirectStrategy.sendRedirect(request, response, uriBuilder.build().encode().toString());
     * 			    return;
     *          }
     * 		    Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
     * 		    String principalName = (currentAuthentication != null) ? currentAuthentication.getName() : "anonymousUser";
     * 		    //TODO，构造OAuth2AuthorizedClient
     * 		    OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
     * 				    authenticationResult.getClientRegistration(), principalName, authenticationResult.getAccessToken(),
     * 				    authenticationResult.getRefreshToken());
     * 		    //TODO,持久化OAuth2AuthorizedClient
     * 		    this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, currentAuthentication, request, response);
     * 		    String redirectUrl = authorizationRequest.getRedirectUri();
     * 		    SavedRequest savedRequest = this.requestCache.getRequest(request, response);
     * 		    if (savedRequest != null) {
     * 			    redirectUrl = savedRequest.getRedirectUrl();
     * 			    this.requestCache.removeRequest(request, response);
     *          }
     *          //TODO,redirect，redirect地址为ClientRegistration中配置的redirectUri
     * 		    this.redirectStrategy.sendRedirect(request, response, redirectUrl);
     * 	    }
     *
     * }
     * public class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
     *      //OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>实现，@see FlSecurityOAuth2Sample/第五
     * 	    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
     *
     *      @Override
     *      public Authentication authenticate(Authentication authentication) throws AuthenticationException {
     * 		    OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
     * 		    OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationResponse();
     * 		    if (authorizationResponse.statusError()) throw new OAuth2AuthorizationException(authorizationResponse.getError());
     * 		    OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange().getAuthorizationRequest();
     * 		    //比较state值
     * 		    if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
     * 			    OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
     * 			    throw new OAuth2AuthorizationException(oauth2Error);
     *          }
     *          //TODO,使用OAuth2AccessTokenResponseClient申请token
     * 		    OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(new OAuth2AuthorizationCodeGrantRequest(authorizationCodeAuthentication.getClientRegistration(),
     * 						authorizationCodeAuthentication.getAuthorizationExchange()));
     *
     * 		    OAuth2AuthorizationCodeAuthenticationToken authenticationResult = new OAuth2AuthorizationCodeAuthenticationToken(
     * 				    authorizationCodeAuthentication.getClientRegistration(),
     * 				    authorizationCodeAuthentication.getAuthorizationExchange(), accessTokenResponse.getAccessToken(),
     * 				    accessTokenResponse.getRefreshToken(), accessTokenResponse.getAdditionalParameters());
     * 		    authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
     * 		    return authenticationResult;
     *    }
     *
     * }
     *
     * 执行流程
     *   a、前端请求 /oauth2/authorization/github
     *   b、OAuth2AuthorizationRequestRedirectFilter处理该请求，返回一个redirect
     *   c、前端处理redirect，重定向到OAuth2 provider的授权页面
     *   d、授权后,OAuth2 provider返回一个redirect，携带code&state参数
     *   e、OAuth2AuthorizationCodeGrantFilter处理携带code&state的redirect请求，获取并持久化token，执行redirect，redirect的地址是ClientRegistration中配置的
     *   f、后端系统提供redirect地址的mapping
     *
     * org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter
     * org.springframework.security.web.header.HeaderWriterFilter
     * org.springframework.web.filter.CorsFilter
     * org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter
     * org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
     * org.springframework.security.web.authentication.AnonymousAuthenticationFilter
     * org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter
     * org.springframework.security.web.access.ExceptionTranslationFilter
     *
     *
     *
     */

}
