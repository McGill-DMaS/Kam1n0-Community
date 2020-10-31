package ca.mcgill.sis.dmas.kam1n0;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfoSummary.ApplicationSummary;
import ca.mcgill.sis.dmas.kam1n0.app.adata.BinaryDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionCommentWrapper;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobInfo;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalJobScheduler;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Comment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra.ObjectFactoryCassandra;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

import org.apache.hadoop.yarn.webapp.hamlet.Hamlet.A;
import org.omg.CORBA.PUBLIC_MEMBER;
import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.util.UriTemplate;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.annotation.PreDestroy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AppPlatform {

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.TYPE)
	public static @interface AppType {
		String value() default "UNK";
	}

	public static enum AccessMode {
		AUTO, READ, WRITE;

		public boolean isRead(String requestMethod) {
			if (this.equals(AUTO))
				return requestMethod.trim().equalsIgnoreCase("GET");
			return this.equals(READ);
		}
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	public static @interface Access {
		AccessMode value() default AccessMode.AUTO;
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	public static @interface Prioritize {
		boolean value() default true;
	}

	@Autowired
	public AppPlatform(GlobalResources res) {

		try {
			spark = res.spark;
			cassandra = res.cassandra;
			disassemblyFactory = res.disassemblyFactory;
			scheduler = res.scheduler;
			objectFactory = AsmObjectFactory.init(spark, cassandra, res.platform_name, res.global_name);
		} catch (Exception e) {
			logger.error("Failed to initialize component " + this.getClass().getName());
		}

	}

	static Logger logger = LoggerFactory.getLogger(AppPlatform.class);
	public SparkInstance spark;
	public CassandraInstance cassandra;
	public AsmObjectFactory objectFactory;
	public DisassemblyFactory disassemblyFactory;
	public LocalJobScheduler scheduler;

	public final static Map<String, Class<? extends ApplicationConfiguration>> appTypes;

	static {
		appTypes = new HashMap<>();
		Reflections reflections = new Reflections(AppPlatform.class.getPackage().getName());
		Set<Class<? extends ApplicationConfiguration>> allConf = reflections
				.getSubTypesOf(ApplicationConfiguration.class);

		allConf.forEach(conf_cls -> {
			try {
				ApplicationConfiguration conf = conf_cls.newInstance();
				appTypes.put(conf.appType(), conf_cls);
			} catch (Exception e) {
				logger.error("Failed to init class " + conf_cls.getName(), e);
			}
		});
	}

	public List<FunctionCommentWrapper> getComments(long rid, long fid) {
		return objectFactory.obj_comments.queryMultiple(rid, fid).collect().stream().map(FunctionCommentWrapper::new)
				.collect(Collectors.toList());
	}

	public final boolean putComment(long appId, Comment comment) {
		comment.userName = comment.userName.trim();
		comment.functionOffset = comment.functionOffset.trim();
		if (comment.comment.length() > 0)
			objectFactory.obj_comments.put(appId, comment);
		else
			objectFactory.obj_comments.del(appId, comment.functionId, comment.functionOffset, comment.userName,
					comment.date);
		return true;
	}

	public FunctionDataUnit getFunctionFlow(long rid, long fid) {
		Function func = getFunction(rid, fid);
		if (func == null)
			return null;
		return new FunctionDataUnit(func, false);
	}

	public Function getFunction(long rid, long fid) {
		Function func = this.objectFactory.obj_functions.querySingle(rid, fid);
		if (func != null)
			func.fill(rid, objectFactory);
		else
			return null;
		return func;
	}

	public ApplicationSummary getSummary(long appId) {
		ApplicationSummary summary = new ApplicationSummary();
		summary.numBinaries = objectFactory.obj_binaries.count(appId);
		summary.numFunctions = objectFactory.obj_functions.count(appId);
		summary.numBasicBlocks = objectFactory.obj_blocks.count(appId);
		return summary;
	}

	public List<LocalDmasJobInfo> listJobProgress(String uname) {
		return scheduler.listJobs(uname);
	}

	public LocalJobProgress getJobProgress(String taskName) {
		return scheduler.getJobProgress(UserController.findUserName(), taskName);
	}

	@Component
	public class PrioritizeInterceptor extends HandlerInterceptorAdapter {

		@Autowired
		private GlobalResources res;

		@Override
		public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
				throws Exception {
			if (handler instanceof HandlerMethod) {
				HandlerMethod handlerMethod = (HandlerMethod) handler;
				if (handlerMethod.hasMethodAnnotation(Prioritize.class)) {
					if (handlerMethod.getMethodAnnotation(Prioritize.class).value()) {
						res.spark.poolPrioritize();
					}
				} else {
					// do nothing. use default FIFO pool.
				}
			}
			return true;
		}
	}

	@Component
	public class AccessControlInterceptor extends HandlerInterceptorAdapter {

		@Autowired
		private AppController appController;

		private UriTemplate template = new UriTemplate("/{appType:.+}/{appId:[-0-9]+}/");

		@Override
		public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
				throws Exception {
			Map<String, String> vals = template.match(request.getRequestURI());
			if (!vals.isEmpty()) {
				String appType = "/" + vals.get("appType");
				String appId = vals.get("appId");
				if (StringResources.isNumeric(appId) && appTypes.containsKey(appType)) {
					String user = UserController.findUserName();
					ApplicationInfo appInfo = appController.getAppInfo(Long.parseLong(appId));
					if (appInfo == null || !appInfo.isOnline) {
						response.sendError(404, "The application is not available.");
						return false;
					}
					boolean canWrite = appInfo.users_wirte.contains(user) || appInfo.owner.equals(user);
					boolean canRead = canWrite || appInfo.users_read.contains(user);
					HandlerMethod handlerMethod = (HandlerMethod) handler;
					if (handlerMethod == null) {
						logger.error("Unknown type of handler: {} {}", handler, handler.getClass());
						response.sendError(403);
						return false;
					}
					Access ann = handlerMethod.getMethod().getAnnotation(Access.class);
					boolean isRead = (ann == null ? AccessMode.AUTO : ann.value()).isRead(request.getMethod());
					if (canRead && isRead)
						return true;
					if (canWrite && !isRead)
						return true;
					response.sendError(403);
					return false;
				} else {
					logger.error(
							"By policy our second level uri are restricted to the users. however this uri cannot find any matches resources. {}",
							request.getRequestURI());
					response.sendError(403);
					return false;
				}
			}
			return true;
		}
	}

	@Configuration
	public static class WebMvcConfigure extends WebMvcConfigurerAdapter {

		@Autowired
		AccessControlInterceptor accInterceptor;

		@Autowired
		PrioritizeInterceptor prioInterceptor;

		@Override
		public void addViewControllers(ViewControllerRegistry registry) {
			registry.addViewController("/").setViewName("forward:/index.html");
			registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
			super.addViewControllers(registry);
		}

		@Override
		public void addInterceptors(InterceptorRegistry registry) {

			registry.addInterceptor(accInterceptor);
			registry.addInterceptor(prioInterceptor);

		}

	}

	public static void main(String[] args) {

		UriTemplate template = new UriTemplate("/{appType:.+}/{appId:[-0-9]+}/");
		String uri = "/sym1n0-clone/-6419340191534907634/aaaa/aaaaa/123123123333";
		System.out.println(template.match(uri));
	}

}
