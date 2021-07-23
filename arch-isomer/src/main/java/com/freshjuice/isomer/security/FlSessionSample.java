package com.freshjuice.isomer.security;

public class FlSessionSample {

    /**
     *依赖
     * spring-session-data-redis
     *  spring-data-redis
     *  spring-session-core
     *
     */

    /**
     *auto-configuration
     * @see org.springframework.boot.autoconfigure.session.SessionAutoConfiguration
     * @see org.springframework.boot.autoconfigure.session.RedisSessionConfiguration
     * @see org.springframework.boot.autoconfigure.session.SessionRepositoryFilterConfiguration
     *configuration,annotation
     * @see org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration
     * @see org.springframework.session.config.annotation.web.http.SpringHttpSessionConfiguration
     *filter and initializer
     * @see org.springframework.session.web.http.SessionRepositoryFilter
     * @see org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer
     *
     *
     *第一: SessionRepositoryFilter的注册
     *1、SpringHttpSessionConfiguration中创建SessionRepositoryFilter的bean
     * @Bean
     * public <S extends Session> SessionRepositoryFilter<? extends Session> springSessionRepositoryFilter(
     * 			SessionRepository<S> sessionRepository) {
     * 		SessionRepositoryFilter<S> sessionRepositoryFilter = new SessionRepositoryFilter<>(sessionRepository);
     * 		sessionRepositoryFilter.setServletContext(this.servletContext);
     * 		sessionRepositoryFilter.setHttpSessionIdResolver(this.httpSessionIdResolver);
     * 		return sessionRepositoryFilter;
     * }
     *2、SessionRepositoryFilterConfiguration中创建FilterRegistrationBean<SessionRepositoryFilter<?>>
     *  FilterRegistrationBean中设置了SessionRepositoryFilter<?>，会将SessionRepositoryFilter<?>写到Servlet Container中
     *  Order可以调用setOrder或者Filter的@Order，拦截路径在其基类的urlPatterns或者DEFAULT_URL_MAPPINGS
     *@Bean
     *FilterRegistrationBean<SessionRepositoryFilter<?>> sessionRepositoryFilterRegistration(SessionProperties sessionProperties,
     *                  SessionRepositoryFilter<?> filter) {
     *
     * 		FilterRegistrationBean<SessionRepositoryFilter<?>> registration = new FilterRegistrationBean<>(filter);
     * 		registration.setDispatcherTypes(getDispatcherTypes(sessionProperties));
     * 		registration.setOrder(sessionProperties.getServlet().getFilterOrder());
     * 		return registration;
     *}
     *3、增加配置
     *spring:
     *  session:
     *     servlet:
     *       ##去掉默认的ERROR,表示不拦截/error，原因@see FlBasicErrorController
     *       filter-dispatcher-types: ASYNC,REQUEST
     *
     *第二: RedisOperationsSessionRepository
     *  RedisHttpSessionConfiguration 中创建 RedisOperationsSessionRepository的bean
     *  @Bean
     *  public RedisOperationsSessionRepository sessionRepository() {
     * 		RedisTemplate<Object, Object> redisTemplate = createRedisTemplate();
     * 	    //TODO,使用RedisTemplate创建RedisOperationsSessionRepository
     * 		RedisOperationsSessionRepository sessionRepository = new RedisOperationsSessionRepository(redisTemplate);
     * 	    //TODO,设置ApplicationEventPublisher
     * 		sessionRepository.setApplicationEventPublisher(this.applicationEventPublisher);
     * 		if (this.defaultRedisSerializer != null) {
     * 			sessionRepository.setDefaultSerializer(this.defaultRedisSerializer);
     *      }
     *      //TODO,Session失效时间,将会设置成redis中spring:session:sessions:的失效时间
     * 		sessionRepository.setDefaultMaxInactiveInterval(this.maxInactiveIntervalInSeconds);
     * 		if (StringUtils.hasText(this.redisNamespace)) {
     * 			sessionRepository.setRedisKeyNamespace(this.redisNamespace);
     *      }
     * 		sessionRepository.setRedisFlushMode(this.redisFlushMode);
     * 		int database = resolveDatabase();
     * 		sessionRepository.setDatabase(database);
     * 		return sessionRepository;
     *  }
     *
     *  //TODO,定时调用RedisOperationsSessionRepository的cleanupExpiredSessions()
     *  @Override
     *  public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
     * 		taskRegistrar.addCronTask(() -> sessionRepository().cleanupExpiredSessions(), this.cleanupCron);
     *  }
     *
     *  @Bean
     *  public RedisMessageListenerContainer redisMessageListenerContainer() {
     * 		RedisMessageListenerContainer container = new RedisMessageListenerContainer();
     * 		container.setConnectionFactory(this.redisConnectionFactory);
     * 		if (this.redisTaskExecutor != null) {
     * 			container.setTaskExecutor(this.redisTaskExecutor);
     *      }
     * 		if (this.redisSubscriptionExecutor != null) {
     * 			container.setSubscriptionExecutor(this.redisSubscriptionExecutor);
     *      }
     *      //监听redis事件
     * 		container.addMessageListener(sessionRepository(), Arrays.asList(
     * 				new ChannelTopic(sessionRepository().getSessionDeletedChannel()),
     * 				new ChannelTopic(sessionRepository().getSessionExpiredChannel())));
     * 		container.addMessageListener(sessionRepository(),
     * 				Collections.singletonList(new PatternTopic(
     * 						sessionRepository().getSessionCreatedChannelPrefix() + "*")));
     * 		return container;
     *  }
     *  需要在redis中配置开启事件通知，如: notify-keyspace-events Egx
     *
     * class RedisOperationsSessionRepository {
     *
     *      //SessionRepositoryFilter中调用，根据sessionId获取Session
     *      @Override
     *      public RedisSession findById(String id) {
     * 		    return getSession(id, false);
     *      }
     *      //SessionRepositoryFilter中调用，根据sessionId删除Session
     *      @Override
     *      public void deleteById(String sessionId) {
     * 		    RedisSession session = getSession(sessionId, true);
     * 		    if (session == null) return;
     *          //删除index信息
     * 		    cleanupPrincipalIndex(session);
     * 		    //删除expires信息
     * 		    this.expirationPolicy.onDelete(session);
     * 		    String expireKey = getExpiredKey(session.getId());
     * 		    this.sessionRedisOperations.delete(expireKey);
     *          //设置session key的过期时间为0
     * 		    session.setMaxInactiveInterval(Duration.ZERO);
     * 		    save(session);
     *      }
     *      //SessionRepositoryFilter中调用，创建Session
     *      @Override
     *      public RedisSession createSession() {
     * 		    Duration maxInactiveInterval = Duration.ofSeconds((this.defaultMaxInactiveInterval != null) ? this.defaultMaxInactiveInterval : MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS);
     * 		    //TODO，创建RedisSession对象
     * 		    RedisSession session = new RedisSession(maxInactiveInterval);
     * 		    session.flushImmediateIfNecessary();
     * 		    return session;
     *      }
     *
     *      //SessionRepositoryFilter中调用，用于保存Session
     *      @Override
     *      public void save(RedisSession session) {
     *          //TODO,调用RedisSession的save
     * 		    session.save();
     * 		    if (session.isNew()) {
     * 			    String sessionCreatedKey = getSessionCreatedChannel(session.getId());
     * 			    //向指定channel发送指定的Message
     * 			    this.sessionRedisOperations.convertAndSend(sessionCreatedKey, session.delta);
     * 			    session.setNew(false);
     *          }
     *      }
     *
     *      //Session实现类
     *      final class RedisSession implements Session {
     *          private final MapSession cached;
     * 		    private Instant originalLastAccessTime;
     * 		    private Map<String, Object> delta = new HashMap<>();
     * 		    private boolean isNew;
     * 		    private String originalPrincipalName;
     * 		    private String originalSessionId;      //构造时等于cached的id，当cached的id变化后，用于和cached的id比较
     *
     *          //save方法
     *          private void save() {
     * 			    saveChangeSessionId();
     * 			    saveDelta();
     *          }
     *          private void saveChangeSessionId() {
     *              //TODO,获取MapSession cached的id，如果等于originalSessionId，则退出; 如果不等于originalSessionId表示id被change了
     * 			    String sessionId = getId();
     * 			    if (sessionId.equals(this.originalSessionId)) return;
     * 			    if (!isNew()) {//TODO,如果isNew=false(不是新的Session)
     * 			        //将redis中保存Session对象的key改名
     * 				    String originalSessionIdKey = getSessionKey(this.originalSessionId);
     * 				    String sessionIdKey = getSessionKey(sessionId);
     * 				    try {
     * 					    RedisOperationsSessionRepository.this.sessionRedisOperations
     * 							    .rename(originalSessionIdKey, sessionIdKey);
     *                  } catch (NonTransientDataAccessException ex) {
     * 					    handleErrNoSuchKeyError(ex);
     *                  }
     *                  //将redis中保存的expire相关的key改名
     * 				    String originalExpiredKey = getExpiredKey(this.originalSessionId);
     * 				    String expiredKey = getExpiredKey(sessionId);
     * 				    try {
     * 					    RedisOperationsSessionRepository.this.sessionRedisOperations
     * 							    .rename(originalExpiredKey, expiredKey);
     *                  } catch (NonTransientDataAccessException ex) {
     * 					    handleErrNoSuchKeyError(ex);
     *                  }
     *              }
     * 			    this.originalSessionId = sessionId; //两者置为相等，这也可以防止一个Request重复调用
     * 			}
     *          private void saveDelta() {
     * 			    if (this.delta.isEmpty()) return;
     * 			    String sessionId = getId();
     * 			    getSessionBoundHashOperations(sessionId).putAll(this.delta);
     * 			    String principalSessionKey = getSessionAttrNameKey(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME);
     * 			    String securityPrincipalSessionKey = getSessionAttrNameKey(SPRING_SECURITY_CONTEXT);
     * 			    if (this.delta.containsKey(principalSessionKey) || this.delta.containsKey(securityPrincipalSessionKey)) {
     * 				    if (this.originalPrincipalName != null) {
     * 					    String originalPrincipalRedisKey = getPrincipalKey(this.originalPrincipalName);
     * 					    RedisOperationsSessionRepository.this.sessionRedisOperations.boundSetOps(originalPrincipalRedisKey).remove(sessionId);
     *                  }
     * 				    String principal = PRINCIPAL_NAME_RESOLVER.resolvePrincipal(this);
     * 				    this.originalPrincipalName = principal;
     * 				    if (principal != null) {
     * 					    String principalRedisKey = getPrincipalKey(principal);
     * 					    RedisOperationsSessionRepository.this.sessionRedisOperations.boundSetOps(principalRedisKey).add(sessionId);
     *                  }
     *              }
     * 			    this.delta = new HashMap<>(this.delta.size());
     * 			    Long originalExpiration = (this.originalLastAccessTime != null)
     * 					? this.originalLastAccessTime.plus(getMaxInactiveInterval())
     * 							.toEpochMilli()
     * 					: null;
     * 			    RedisOperationsSessionRepository.this.expirationPolicy.onExpirationUpdated(originalExpiration, this);
     * 			}
     *
     *      }
     *
     * }
     *
     *
     *第三: 与spring security
     * 1、SessionRegistry
     * 使用SpringSessionBackedSessionRegistry,替代SessionRegistryImpl {@link FlSecuritySample}/第十: session-management/4
     *     //TODO,这个Repository就是上述的RedisOperationsSessionRepository，所以Registry默认就是使用Repository
     *     @Autowired
     *     private FindByIndexNameSessionRepository<S> sessionRepository;
     *     @Bean
     *     public SpringSessionBackedSessionRegistry<S> springSessionBackedSessionRegistry() {
     *         return new SpringSessionBackedSessionRegistry<>(this.sessionRepository);
     *     }
     *     sessionRegistry(springSessionBackedSessionRegistry())
     *
     *TODO,内存泄漏问题: 重复调用/login接口并且携带上一次调用的s-token,wrappedSession中Session被设置成n-id,HttpSession(持久化在redis中的Session对象)触发key改名:n-id将o-id替换掉了
     *      但是index中o-id并没有被清除，要防止已登录的重复登录
     *
     *TODO,重复调用/login接口并且不携带上一次调用的s-token: 新创建wrappedSession,redis中新HttpSession(spring:session:sessions:n-id)和index中写入n-id
     *      并且原来的HttpSession(spring:session:sessions:o-id)还在,被打上了过期标记，index中o-id还在
     *      1、如果客户端使用s-token=o-id访问，请求到ConcurrentSessionFilter中将能够识别过期标记，从而触发Session的invalidate，能够很好的清理redis中存储的内容
     *      2、如果没有第1中的情况触发，redis中将始终保存着数据，而当spring:session:sessions:expires:o-id过期时，清除index中对应o-id, @see RedisOperationsSessionRepository.onMessage
     *
     *TODO,调用非/login接口,不带s-token,带remember-me,将触发remember-me逻辑:remember-me登录成功后,新创建wrappedSession,redis中新HttpSession(spring:session:sessions:n-id)和index中写入n-id
     *     并且原来的HttpSession(spring:session:sessions:o-id)还在,被打上了过期标记，index中o-id还在
     *     1、如果客户端使用s-token=o-id访问，请求到ConcurrentSessionFilter中将能够识别过期标记，从而触发Session的invalidate，能够很好的清理redis中存储的内容
     *     2、如果没有第1中的情况触发，redis中将始终保存着数据，而当spring:session:sessions:expires:o-id过期时，清除index中对应o-id
     *
     *
     *
     * 第四: SessionRepositoryFilter解读
     * SessionRepositoryFilter先于security chain执行 {
     *      //RedisOperationsSessionRepository
     *      private final SessionRepository<S> sessionRepository;
     *
     *      protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
     * 			            throws ServletException, IOException {
     * 			//request中保存sessionRepository对象
     *          request.setAttribute(SESSION_REPOSITORY_ATTR, this.sessionRepository);
     *          /TODO，将Request,Response wrapper
     * 		    SessionRepositoryRequestWrapper wrappedRequest = new SessionRepositoryRequestWrapper(request, response, this.servletContext);
     * 		    SessionRepositoryResponseWrapper wrappedResponse = new SessionRepositoryResponseWrapper(wrappedRequest, response);
     * 		    try {
     * 		    //TODO，chain
     * 			    filterChain.doFilter(wrappedRequest, wrappedResponse);
     *          } finally {
     *          //TODO，chain执行完调用commitSession方法，注意: 如果chain中response已经commit了，则如下"onResponseCommitted"也会执行request.commitSession()
     * 			    wrappedRequest.commitSession();
     *          }
     *      }
     * }
     * 1、Response的wrapper
     * //如果在chain执行中response已经commit，则此方法将被触发
     * @Override
     * protected void onResponseCommitted() {
     * 		this.request.commitSession();
     * }
     * 2、Request的wrapper
     * final class SessionRepositoryRequestWrapper extends HttpServletRequestWrapper {
     *      //TODO,HttpSessionAdapter将Spring的Session适配成servlet的HttpSession
     *      private final class HttpSessionWrapper extends HttpSessionAdapter<S> {
     * 			   HttpSessionWrapper(S session, ServletContext servletContext) {
     * 				   super(session, servletContext);
     *             }
     *             //当调用invalidate方法时
     *             @Override
     *             public void invalidate() {
     *                 //调用HttpSessionAdapter，设置invalidate标记
     * 				   super.invalidate();
     * 				   //TODO,设置SessionRepositoryRequestWrapper中的requestedSessionInvalidated=true
     * 				   SessionRepositoryRequestWrapper.this.requestedSessionInvalidated = true;
     * 				   //TODO,Request的Attr域中清除CURRENT_SESSION_ATTR: removeAttribute(CURRENT_SESSION_ATTR)
     * 				   setCurrentSession(null);
     * 				   //TODO,清除SessionRepositoryRequestWrapper中缓存，requestedSessionCached=false,requestedSessionId=null,requestedSession=null
     * 				   clearRequestedSessionCache();
     * 				   //TODO,调用sessionRepository的deleteById方法
     * 				   SessionRepositoryFilter.this.sessionRepository.deleteById(getId());
     *             }
     *      }
     *
     *
     *      //TODO，重写getSession方法,返回HttpSessionWrapper对象
     *      @Override
     *      public HttpSessionWrapper getSession(boolean create) {
     *          //TODO,从Request的Attr域中拿CURRENT_SESSION_ATTR: getAttribute(CURRENT_SESSION_ATTR)
     * 			HttpSessionWrapper currentSession = getCurrentSession();
     * 			if (currentSession != null) return currentSession;
     *
     *          //TODO,解析sessionId，根据sessionId获取Spring的Session
     *          //如果没有Session的缓存,使用httpSessionIdResolver解析sessionId，调用sessionRepository的findById根据sessionId获取Session对象，将Session对象缓存
     *          //如果有Session的缓存，从缓存中取
     * 			S requestedSession = getRequestedSession();
     * 			if (requestedSession != null) {
     * 		        //TODO,如果Request中没有INVALID_SESSION_ID_ATTR
     * 				if (getAttribute(INVALID_SESSION_ID_ATTR) == null) {
     * 			        //Session对象设置lastAccessedTime
     * 					requestedSession.setLastAccessedTime(Instant.now());
     * 				    //TODO,SessionRepositoryRequestWrapper中requestedSessionIdValid设置为true(有效)
     * 					this.requestedSessionIdValid = true;
     * 				    //TODO,根据Session对象创建HttpSessionWrapper，并设置在Request的CURRENT_SESSION_ATTR: setAttribute(CURRENT_SESSION_ATTR, currentSession)
     * 					currentSession = new HttpSessionWrapper(requestedSession, getServletContext());
     * 					currentSession.setNew(false);  //不是new，因为是根据sessionId找到的Session对象，说明是之前创建的
     * 					setCurrentSession(currentSession);
     * 					return currentSession;
     *               }
     *           } else { //TODO,如果根据sessionId没有找到Spring的Session,在Request中设置INVALID_SESSION_ID_ATTR
     * 				 setAttribute(INVALID_SESSION_ID_ATTR, "true");
     *           }
     * 			 if (!create) {  //是否新创建标记
     * 				 return null;
     *           }
     * 			 //TODO，使用sessionRepository创建Spring的Session
     * 			 S session = SessionRepositoryFilter.this.sessionRepository.createSession();
     * 			 session.setLastAccessedTime(Instant.now());
     * 			 //TODO,创建HttpSessionWrapper封装Session,并设置在Request的CURRENT_SESSION_ATTR: setAttribute(CURRENT_SESSION_ATTR, currentSession)
     * 			 currentSession = new HttpSessionWrapper(session, getServletContext());
     * 			 setCurrentSession(currentSession);
     * 			 return currentSession;
     *      }
     *
     *      //TODO，重写changeSessionId
     *      @Override
     *      public String changeSessionId() {
     *          //获取Spring的Session
     * 			HttpSession session = getSession(false);
     * 			if (session == null) {
     * 				throw new IllegalStateException(
     * 						"Cannot change session ID. There is no session associated with this request.");
     *          }
     *          //获取Session对象，调用Session对象的changeSessionId
     * 			return getCurrentSession().getSession().changeSessionId();
     *      }
     *
     *      //TODO，重写getRequestedSessionId
     *      @Override
     *      public String getRequestedSessionId() {
     *          //先取缓存的sessionId
     * 			if (this.requestedSessionId == null) {
     * 			    //解析sessionId，根据sessionId获取Session对象，并设置缓存(详见getSession中说明)
     * 				getRequestedSession();
     *          }
     * 			return this.requestedSessionId;
     *      }
     *      //TODO,重写isRequestedSessionIdValid
     *      @Override
     *      public boolean isRequestedSessionIdValid() {
     *          //先获取valid标记: true-有效
     * 			if (this.requestedSessionIdValid == null) {
     * 		        //解析sessionId，根据sessionId获取Session对象，并设置缓存(详见getSession中说明)
     * 				S requestedSession = getRequestedSession();
     * 				if (requestedSession != null) { //如果Session不为空
     * 					requestedSession.setLastAccessedTime(Instant.now());
     *              }
     *              //如果Session不为空，设置requestedSessionIdValid=true
     * 				return isRequestedSessionIdValid(requestedSession);
     *          }
     * 			return this.requestedSessionIdValid;
     *      }
     *
     *
     *
     * }
     * 3.wrappedRequest.commitSession() {
     *     //TODO，commitSession调用
     *     private void commitSession() {
     *          //TODO,从Request的Attr域中拿CURRENT_SESSION_ATTR: getAttribute(CURRENT_SESSION_ATTR)
     * 			HttpSessionWrapper wrappedSession = getCurrentSession();
     * 			if (wrappedSession == null) { //如果没有CURRENT_SESSION_ATTR ，可以等同于说Session对象没有被创建
     * 				if (isInvalidateClientSession()) {//SessionRepositoryRequestWrapper的requestedSessionInvalidated标记为true（当Session的invalidate方法调用时设置为true）
     * 				    //注销客户端sessionId
     * 					SessionRepositoryFilter.this.httpSessionIdResolver.expireSession(this, this.response);
     *              }
     *          } else {//TODO,如果HttpSessionWrapper 不为空
     *              //获取Spring的Session对象
     * 				S session = wrappedSession.getSession();
     * 			    //TODO,清空缓存,requestedSessionCached=false,requestedSession=null,requestedSessionId=null
     * 				clearRequestedSessionCache();
     * 			    //TODO,使用sessionRepository保存Session对象
     * 				SessionRepositoryFilter.this.sessionRepository.save(session);
     *              //TODO,如果Session的id和请求中的sessionId不一样，将Session的id写回客户端
     * 				String sessionId = session.getId();
     * 				if (!isRequestedSessionIdValid() || !sessionId.equals(getRequestedSessionId())) {
     * 					SessionRepositoryFilter.this.httpSessionIdResolver.setSessionId(this, this.response, sessionId);
     *              }
     *          }
     *     }
     *
     * }
     * 4、原理推演
     * SessionRepositoryFilter中对Request wrapper: SessionRepositoryRequestWrapper,重写了getSession(...)等方法
     *                         对HttpSession进行适配，HttpSessionWrapper，重写了invalidate方法
     *
     * wrappedRequest随chain下发
     *    1、chain中调用wrappedRequest.getSession(...)方法(也可能没有调用)
     *    2、回到SessionRepositoryFilter调用commitSession()，并且如果chain中Response已经committed，commitSession()会先一步被调用 (即可能commitSession()被调用两次)
     *
     *    1、chain中调用wrappedSession的invalidate()方法(也可能没调用)
     *    2、回到SessionRepositoryFilter调用commitSession()，并且如果chain中Response已经committed，commitSession()会先一步被调用 (即可能commitSession()被调用两次)
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     *
     */



}
