package com.freshjuice.poner.security;

public class FlSecurityOAuth2Sample {
    /**
     *spring security + OAuth2
     *
     *OAuth2
     *   Resource Owner(User)授权Client访问其在Resource Server中的资源
     *spring security的OAuth2支持
     *   spring-security-oauth2-core.jar
     *   spring-security-oauth2-client.jar
     *   spring-security-oauth2-authorization-server.jar  TODO,实验性的
     *   spring-security-oauth2-resource-server.jar
     *   spring-security-oauth2-jose.jar
     *spring cloud security,TODO?
     *
     */

    /**
     *认证系统抽象
     *  1、使用spring security 构建 OAuth2 Authorization Server
     *  2、Resource Server校验资源权限，网关/服务单元
     *  @see arch-oauth2-auth/FlSecurityAuthSample
     */

    /**
     * 关于版本选择和废弃的依赖等等:
     *    https://blog.csdn.net/qq_35425070/article/details/104180112
     *
     * spring-cloud-starter-oauth2、spring-cloud-starter-security
     *    将在spring-cloud Hoxton.SR2被废弃的依赖:
     * spring-cloud-security
     *    的废弃？？？
     *
     * 被废弃的依赖: org.springframework.security.oauth:spring-security-oauth2
     *     逐渐由spring security下的spring-security-oauth2-**代替
     *     spring security 5.3之前版本没有提供spring-security-oauth2-authorization-server
     *     spring security 5.5版本提供的spring-security-oauth2-authorization-server仍然是实验性的
     * 从spring-security-oauth2迁移到spring-security的oauth2
     *   https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide
     *   TODO? note: client、login、resource-server得到支持，but，authorization-server是实验性的
     *
     * 可以预见到，Spring官方未来会废弃一切与 security 相关的子项目并迁移至 Spring Security 中
     *
     *
     */

    /**
     *OAuth2
     * 概念  Client,Resource Owner(User),Authorization Server,Resource Server
     *      Resource Owner(User)授权Client访问其在Resource Server中的资源
     * OAuth2授权机制
     *               A: Authorization Request ---->       Resource Owner(User)
     *               B: Authorization Grant   <----       Resource Owner(User)
     *
     *               C: Authorization Grant   ---->       Authorization Server
     * Client        D: Access Token          <----       Authorization Server
     *
     *               E: Access Token          ---->       Resource Server
     *               F: Protected Resource    <----       Resource Server
     *
     * OAuth2授权流程  四种授权方式可选择: 授权码模式(authorization code)，简化模式(implicit)，密码模式(password credentials)，客户端凭证模式(client credentials)
     *  1、授权码模式流程
     *    1)、Client(前端,App)引导User跳转到Authorization Server的认证授权页面
     *        跳转授权地址: 由Authorization Server提供
     *        携带的参数: response_type=code  //表示是授权码模式
     *                  client_id=id        //Client在Authorization Server注册后获取到的应用标记
     *                  redirect_uri=url    //授权成功/失败后Authorization Server重定向的地址(一般是后端接口地址) TODO?前端或者App提供地址自己实现也可以，但是后端系统理应有这个功能
     *                  scope=read,write    //授权范围,值的具体意义由Authorization Server定义
     *                  state=params        //Authorization Server原封不动的返回这个参数值，该参数用于防止csrf攻击: Client验证该参数从而确定的确是Authorization Server的响应
     *                                      //1、如果跳转授权页面走https，一般需要传递state参数，Authorization Server重定向后验证state
     *                                      //2、如果跳转授权页面走http，传递state参数可能被拦截并窃取，此时的做法: 跳转授权页面发送加密的state,Authorization Server返回解密后的state
     *
     *    2)、在"认证授权页面"，User确认授权并提交后，Authorization Server Response一个"重定向": HTTP/1.1 302 Location redirect_uri?state=..&code=.., Client(前端，app)收到"重定向"即访问重定向地址
     *        重定向地址: 一般是后端提供的接口地址
     *        携带的参数: state=params
     *                  code=授权码
     *
     *    3)、Client(一般是后端)向Authorization Server申请token,Authorization Server签发token并响应token数据
     *        申请token地址: 由Authorization Server提供
     *        携带的参数: grant_type=authorization_code  //授权码模式
     *                  code=授权码                     //授权码
     *                  client_id=id                   //Client在Authorization Server注册后获取到的应用标记
     *                  client_secret                  //Client在Authorization Server注册后获取到的应用凭证
     *                  redirect_uri=url               //与第一步填写一致即可，估计是用做校验的吧 TODO?待验证？？？
     *        申请Token请求的响应: json格式
     *                  {
     *                      "access_token":"ACCESS_TOKEN",
     *                      "token_type":"bearer",
     *                      "expires_in":2592000,
     *                      "refresh_token":"REFRESH_TOKEN",
     *                      "scope":"read",
     *                      "uid":100101,
     *                      "info":{...}
     *                  }
     *       TODO? 前后端职责划分？native App上处理认证授权html页面？
     *    4)、Client使用Access Token访问User在Resource Server上的信息
     *  2、简化模式流程
     *    1)、Client(前端,App)引导User跳转到Authorization Server的认证授权页面
     *        response_type=token //表示是简化模式
     *        其他说明见 授权码模式
     *    2)、在"认证授权页面"，User确认授权并提交后，Authorization Server Response一个"重定向": HTTP/1.1 302 Location redirect_uri?state=..&access_token=..&refresh_token=..
     *  3、密码模式流程
     *    1)、Client(前端,App)展示一个login页面，User输入username和password，Client(前端,App)申请token
     *        申请token地址: 由Authorization Server提供
     *        携带的参数: grant_type=password    //密码模式
     *                  user_name=principal    //用户标记
     *                  client_id=client_id    //client_id
     *                  password=credentials   //用户凭证
     *                  scope=read,write       //授权范围,值的具体意义由Authorization Server定义
     *        请求响应: json格式
     *            {
     *                  "access_token":"2YotnFZFEjr1zCsicMWpAA",
     *                  "token_type":"example",
     *                  "expires_in":3600,
     *                  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
     *                  "scope":"read"
     *                  "example_parameter":"example_value"
     *            }
     *  4、客户端凭证模式
     *     1)、Client申请token
     *         申请token地址: 由Authorization Server提供
     *         携带的参数: grant_type=client_credentials    //客户端凭证模式
     *                   client_id=client_id               //client_id
     *                   scope=read,write       //授权范围,值的具体意义由Authorization Server定义
     *         请求响应: json格式
     *               {...}
     * token过期刷新
     *   由前端还是后端识别token过期？TODO？
     *     刷新地址: 由Authorization Server提供
     *     携带的参数: grant_type=refresh_token
     *               refresh_token=refresh_token
     *     请求响应刷新后的token {...}
     *
     * 第三方登录: github登录例子   https://www.ruanyifeng.com/blog/2019/04/github-oauth.html
     * 
     *
     */


    /**OAuth2 Client
     *第一: ClientRegistration,ClientRegistrationRepository
     * public final class ClientRegistration implements Serializable {
     *      private String registrationId;     //id
     *      private String clientId;           //client_id
     *      private String clientSecret;       //client_secret
     *      private ClientAuthenticationMethod clientAuthenticationMethod;  //client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt and none
     *      private AuthorizationGrantType authorizationGrantType;  // The OAuth 2.0 Authorization Framework defines four Authorization Grant types. The supported values are authorization_code, client_credentials, password
     *      private String redirectUri;               //redirect地址
     *      private Set<String> scopes;               //scope
     *      private ProviderDetails providerDetails;
     *      private String clientName;
     *
     *      public class ProviderDetails {
     *         private String authorizationUri;             //申请code的uri
     *         private String tokenUri;                     //申请token的uri
     *         private UserInfoEndpoint userInfoEndpoint;
     *         private String jwkSetUri;                    //The URI used to retrieve the JSON Web Key (JWK) Set from the Authorization Server
     *         private String issuerUri;                    //Returns the issuer identifier uri for the OpenID Connect 1.0 provider or the OAuth 2.0 Authorization Server
     *         private Map<String, Object> configurationMetadata;
     *
     *         public class UserInfoEndpoint {
     *             private String uri;                      //申请token成功后，调用此地址获取User信息
     *             private AuthenticationMethod authenticationMethod;  //access_token的认证方式:  header, form and query
     *             private String userNameAttributeName;   //The name of the attribute returned in the UserInfo Response that references the Name or Identifier of the end-user
     *         }
     * }
     * public interface ClientRegistrationRepository {
     *     ClientRegistration findByRegistrationId(String registrationId)
     * }
     * public final class InMemoryClientRegistrationRepository {
     *     //内存中Map
     *     private final Map<String, ClientRegistration> registrations;
     * }
     * 一般使用InMemoryClientRegistrationRepository即可
     * 配置文件中配置形式: spring.security.oauth2.client.registration.[registrationId]... 将加载生成ClientRegistration
     *
     *第二: OAuth2AuthorizedClient,OAuth2AuthorizedClientRepository,OAuth2AuthorizedClientService
     * public class OAuth2AuthorizedClient implements Serializable {
     *      //代表 Authorized Client: when Client has accessed User's protected resources
     *
     *      private final ClientRegistration clientRegistration;  //ClientRegistration
     * 	    private final String principalName;                   //User的principalName
     * 	    private final OAuth2AccessToken accessToken;          //access_token
     * 	    private final OAuth2RefreshToken refreshToken;        //refresh_token
     * }
     * public interface OAuth2AuthorizedClientRepository {
     *      //查询
     *      <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, Authentication principal,
     * 																HttpServletRequest request);
     *      //保存
     *      void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal,
     * 								HttpServletRequest request, HttpServletResponse response);
     * 		//清除
     * 		void removeAuthorizedClient(String clientRegistrationId, Authentication principal,
     * 								HttpServletRequest request, HttpServletResponse response);
     * }
     * HttpSessionOAuth2AuthorizedClientRepository类,将OAuth2AuthorizedClient保存在session,弃用...
     * AuthenticatedPrincipalOAuth2AuthorizedClientRepository类，如果authenticated，使用OAuth2AuthorizedClientService(默认InMemoryOAuth2AuthorizedClientService)，否则，使用HttpSessionOAuth2AuthorizedClientRepository类
     * TODO,自定义OAuth2AuthorizedClientRepository
     *
     * 第三: OAuth2AuthorizedClientManager,OAuth2AuthorizedClientProvider
     * public interface OAuth2AuthorizedClientManager {
     *      OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest);
     * }
     * public final class DefaultOAuth2AuthorizedClientManager {
     *      //ClientRegistrationRepository
     *      private final ClientRegistrationRepository clientRegistrationRepository;
     *      //OAuth2AuthorizedClientRepository
     * 	    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
     *      //OAuth2AuthorizedClientProvider
     * 	    private OAuth2AuthorizedClientProvider authorizedClientProvider;
     *      //?
     * 	    private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper;
     *
     * 	    private OAuth2AuthorizationSuccessHandler authorizationSuccessHandler;
     *
     * 	    private OAuth2AuthorizationFailureHandler authorizationFailureHandler;
     *      ...
     * }
     * public interface OAuth2AuthorizedClientProvider {
     *      OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context);
     * }
     * OAuth2AuthorizedClientProviderBuilder: build a DelegatingOAuth2AuthorizedClientProvider which compose one or more provider
     * AuthorizationCodeOAuth2AuthorizedClientProvider //do nothing,他的逻辑在OAuth2AuthorizationCodeGrantFilter中
     * RefreshTokenOAuth2AuthorizedClientProvider {
     *     private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> accessTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
     * }
     * PasswordOAuth2AuthorizedClientProvider {
     *     private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient = new DefaultPasswordTokenResponseClient();
     * }
     *
     *
     * 第四: OAuth2AuthorizationRequest,OAuth2AuthorizationRequestResolver,AuthorizationRequestRepository
     * public final class OAuth2AuthorizationRequest implements Serializable {
     *      //代表 OAuth 2.0 Authorization Request when authorization code grant type or implicit grant type
     *
     *      private String authorizationUri;
     * 	    private AuthorizationGrantType authorizationGrantType;
     * 	    private OAuth2AuthorizationResponseType responseType;
     * 	    private String clientId;
     * 	    private String redirectUri;
     * 	    private Set<String> scopes;
     * 	    private String state;
     * 	    private Map<String, Object> additionalParameters;
     * 	    private String authorizationRequestUri;
     * 	    private Map<String, Object> attributes;
     *      ...
     * }
     * public interface OAuth2AuthorizationRequestResolver {
     *      //解析并创建 OAuth2AuthorizationRequest
     *      OAuth2AuthorizationRequest resolve(HttpServletRequest request);
     *      OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId);
     * }
     * 默认实现DefaultOAuth2AuthorizationRequestResolver,TODO: 使用此默认实现即可
     * public final class DefaultOAuth2AuthorizationRequestResolver {
     *      private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
     *      private static final char PATH_DELIMITER = '/';
     *      //TODO,ClientRegistrationRepository
     * 	    private final ClientRegistrationRepository clientRegistrationRepository;
     * 	    //TODO,路径匹配器，默认OAuth2AuthorizationRequestRedirectFilter中 /oauth2/authorization/{registrationId}
     * 	    private final AntPathRequestMatcher authorizationRequestMatcher;
     * 	    //TODO,base64生成state
     * 	    private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
     *      //TODO,定义Consumer
     * 	    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer = (customizer) -> {
     *      };
     *
     *     @Override
     *     public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
     *          //请求路径匹配并解析请求路径中{registrationId}
     *          String registrationId = this.resolveRegistrationId(request);
     * 		    if (registrationId == null) return null;
     * 		    //request.getParameter("action");
     * 		    String redirectUriAction = getAction(request, "login");
     * 		    return resolve(request, registrationId, redirectUriAction);
     *     }
     *     private OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId, String redirectUriAction) {
     * 		 if (registrationId == null) return null;
     *       //TODO,使用ClientRegistrationRepository，根据registrationId获取ClientRegistration
     * 		 ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
     * 		 if (clientRegistration == null) throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
     *       //TODO，构造OAuth2AuthorizationRequest,additionalParameters中保存registrationId
     *       Map<String, Object> attributes = new HashMap<>();
     * 		 attributes.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
     * 		 OAuth2AuthorizationRequest.Builder builder = getBuilder(clientRegistration, attributes);
     *       //TODO,获取ClientRegistration的redirectUri
     * 		 String redirectUriStr = expandRedirectUri(request, clientRegistration, redirectUriAction);
     *
     * 		 builder.clientId(clientRegistration.getClientId())
     * 				.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
     * 				.redirectUri(redirectUriStr)
     * 				.scopes(clientRegistration.getScopes())
     * 				.state(this.stateGenerator.generateKey())
     * 				.attributes(attributes);
     *       //TODO,consumer此builder
     * 		 this.authorizationRequestCustomizer.accept(builder);
     * 		 return builder.build();
     * 	   }
     * }
     * AuthorizationRequestRepository: 持久化OAuth2AuthorizationRequest
     * public interface AuthorizationRequestRepository<T extends OAuth2AuthorizationRequest> {
     *      T loadAuthorizationRequest(HttpServletRequest request);
     *      void saveAuthorizationRequest(T authorizationRequest, HttpServletRequest request, HttpServletResponse response);
     *      T removeAuthorizationRequest(HttpServletRequest request);
     *      default T removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
     * 		    return removeAuthorizationRequest(request);
     *      }
     * }
     * 默认实现类: HttpSessionOAuth2AuthorizationRequestRepository,在HttpSession中保存,TODO:需要重写
     *
     * 第五: OAuth2AccessTokenResponseClient
     * //申请access_token
     * public interface OAuth2AccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest> {
     *      OAuth2AccessTokenResponse getTokenResponse(T authorizationGrantRequest);
     * }
     * public abstract class AbstractOAuth2AuthorizationGrantRequest {
     * 	    private final AuthorizationGrantType authorizationGrantType;
     * 	    private final ClientRegistration clientRegistration;
     * }
     * public final class OAuth2AccessTokenResponse {
     * 	    private OAuth2AccessToken accessToken;
     * 	    private OAuth2RefreshToken refreshToken;
     * 	    private Map<String, Object> additionalParameters;
     * }
     * 1、授权码模式的实现类: DefaultAuthorizationCodeTokenResponseClient
     * public final class DefaultAuthorizationCodeTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
     *      //构造请求参数
     *      private Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> requestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
     * 	    private RestOperations restOperations;
     * }
     * OAuth2AuthorizationCodeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {
     *     ...
     * }
     * 2、refresh token模式(刷新token)的实现类: DefaultRefreshTokenTokenResponseClient
     * public final class DefaultRefreshTokenTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> {
     *      //构造请求参数
     *      private Converter<OAuth2RefreshTokenGrantRequest, RequestEntity<?>> requestEntityConverter = new OAuth2RefreshTokenGrantRequestEntityConverter();
     * 	    private RestOperations restOperations;
     * }
     * public class OAuth2RefreshTokenGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {
     * 	    private final OAuth2AccessToken accessToken;
     * 	    private final OAuth2RefreshToken refreshToken; //如果response没有refresh_token，就设置成此值
     * 	    private final Set<String> scopes;
     * }
     * 3、password模式的实现类: DefaultPasswordTokenResponseClient
     * public final class DefaultPasswordTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> {
     *      //构造请求参数
     *      private Converter<OAuth2PasswordGrantRequest, RequestEntity<?>> requestEntityConverter = new OAuth2PasswordGrantRequestEntityConverter();
     * 	    private RestOperations restOperations;
     * }
     * public class OAuth2PasswordGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {
     * 	    private final String username;
     * 	    private final String password;
     * }
     * 4、JWT: DefaultJwtBearerTokenResponseClient ??
     *
     *
     *
     *
     */


}
