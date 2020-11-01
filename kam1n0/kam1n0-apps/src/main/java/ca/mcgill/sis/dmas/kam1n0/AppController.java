package ca.mcgill.sis.dmas.kam1n0;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.google.common.collect.ImmutableMap;
import com.microsoft.z3.Context;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.Prioritize;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfoSummary;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfoValidator;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserInfo;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileServingUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.MVCUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.ModelAndFragment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra.ObjectFactoryCassandra;


@Controller
public class AppController {

	@Autowired
	private UserController userController;

	@Autowired
	private AppPlatform platform;

	@Autowired
	public AppController(GlobalResources res) {
		try {
			global_key = res.global_key;
			appsFactory = new ObjectFactoryCassandra<ApplicationInfo>(res.cassandra, res.spark);
			appsFactory.init(res.platform_name, res.global_name, ApplicationInfo.class);
		} catch (Exception e) {
			logger.error("Failed to initialize component " + this.getClass().getName());
		}
	}

	@Autowired
	public ApplicationInfoValidator validator;
	private Long global_key = -1l;
	private static Logger logger = LoggerFactory.getLogger(AppController.class);
	private ObjectFactoryMultiTenancy<ApplicationInfo> appsFactory;
	public final static String FRAG_APP_CONF = "platform/fragments/app_conf";
	public final static String FRAG_APP_EDIT = "platform/fragments/app_edit";
	public final static String FRAG_APP_LIST = "platform/fragments/app_list";

	public ApplicationInfo getAppInfo(long app_id) {
		appsFactory.prioritize();
		return appsFactory.querySingle(global_key, app_id);
	}

	public ApplicationInfoSummary getAppInfoSummary(long app_id) {
		appsFactory.prioritize();
		ApplicationInfo info = appsFactory.querySingle(global_key, app_id);
		return new ApplicationInfoSummary(info, platform.getSummary(app_id));
	}

	public List<LocalDmasJobInfo> getAllProgress() {
		String uname = UserController.findUserName();
		return platform.scheduler.listJobs(uname);
	}

	public List<ApplicationInfoSummary> getAppInfo(Collection<Long> keys) {
		return keys.parallelStream().map(key -> getAppInfoSummary(key)).filter(info -> info != null)
				.collect(Collectors.toList());
	}

	public List<ApplicationInfo> getAppInfoOnly(Collection<Long> keys) {
		return keys.parallelStream().map(key -> getAppInfo(key)).filter(info -> info != null)
				.collect(Collectors.toList());
	}

	long addAppInfo(ApplicationInfo info) {
		info.appId = UUID.randomUUID().getLeastSignificantBits();
		info.creationDate = new Date();
		appsFactory.put(global_key, info);
		return info.appId;
	}

	public void deleteAppInfo(long appId) {
		appsFactory.del(global_key, appId);
		userController.dropApp(appId);
	}

	public boolean updateApplicationInstance(ApplicationInfo info) {
		// one can only update basic information (a copy):
		ApplicationInfo info_old = getAppInfo(info.appId);
		info_old.users_read = info.users_read;
		info_old.users_wirte = info.users_wirte;
		info_old.name = info.name;
		info_old.title = info.title;
		info_old.description = info.description;
		info_old.isPrivate = info.isPrivate;
		info_old.isOnline = info.isOnline;
		appsFactory.put(global_key, info_old);
		return true;
	}
	
	public boolean updateFullApplicationInstance(ApplicationInfo info) {
		// one can only update basic information (a copy):
		ApplicationInfo info_old = getAppInfo(info.appId);
		info_old.users_read = info.users_read;
		info_old.users_wirte = info.users_wirte;
		info_old.name = info.name;
		info_old.title = info.title;
		info_old.description = info.description;
		info_old.isPrivate = info.isPrivate;
		info_old.isOnline = info.isOnline;
		info_old.setConfiguration(info.configuration);
		appsFactory.put(global_key, info_old);
		return true;
	}

	public ApplicationConfiguration getAppSpecificConfFrag(String type) throws Exception {
		try {
			Class<? extends ApplicationConfiguration> conf_cls = AppPlatform.appTypes.get(type);
			ApplicationConfiguration conf = conf_cls.newInstance();
			return conf;
		} catch (Exception e) {
			AppPlatform.logger.error("Create application specific form failed.", e);
			throw new Exception("Invalid application type.");
		}
	}

	@Prioritize
	@GetMapping("/createApp")
	public ModelAndView showApplicationForm(@ModelAttribute("confObj") final ApplicationInfo info, Model model) {
		try {
			model.addAttribute("confObj", info);
			model.addAttribute("applicationTypes", AppPlatform.appTypes.keySet());
			model.addAttribute("appConfForm", null);
			if (info.applicationType != null && info.applicationType.trim().length() > 0) {
				info.configuration = getAppSpecificConfFrag(info.applicationType);
				model.addAttribute("appConfForm", info.configuration.createView());
			}
			model.addAttribute("edit", false);
			return MVCUtils.wrapAuthenticatedHomePage("Create an Application.", "Please fill the required information.",
					new ModelAndFragment(FRAG_APP_CONF, model));
		} catch (Exception e) {
			AppPlatform.logger.error("Failed to create application form..", e);
			return MVCUtils.errorMV("Failed to create application form.");
		}
	}

	@Prioritize
	@PostMapping("/createApp")
	public ModelAndView submitApplicationForm(@ModelAttribute("confObj") final ApplicationInfo info,
			BindingResult bindingResult, Model model) {
		try {
			validator.validate(info, bindingResult);
			if (bindingResult.hasErrors()) {
				if (info.configuration != null)
					model.addAttribute("appConfForm", info.configuration.createView());
				model.addAttribute("confObj", info);
				model.addAttribute("applicationTypes", AppPlatform.appTypes.keySet());
				model.addAttribute("edit", false);
				return MVCUtils.wrapAuthenticatedHomePage("Create an Application.", "Please correct the following errors.",
						new ModelAndFragment(FRAG_APP_CONF, model));
			}
			info.owner = UserController.findUserName();
			long id = this.addAppInfo(info);
			userController.addApp(id, info.name);
			model.addAttribute("edit", false);
			return MVCUtils.redirectMV("/userHome");
		} catch (Exception e) {
			logger.error("Failed to create application.", e);
			return MVCUtils.errorMV("Failed to create application {}", e.getMessage());
		}
	}

	@Prioritize
	@PostMapping("/toggleApp")
	public @ResponseBody void submitApplicationForm(@RequestParam("appId") final long appId,
			@RequestParam("online") final boolean on) {
		try {
			ApplicationInfo info = this.getAppInfo(appId);
			info.isOnline = on;
			this.updateApplicationInstance(info);
		} catch (Exception e) {
			logger.error("Failed to toggle application.", e);
		}
	}

	public ModelAndFragment createAppList() {
		UserInfo user = UserController.findUser();
		List<ApplicationInfoSummary> apps = getAppInfo(user.ownedApps);
		List<ApplicationInfoSummary> apps_shared = getAppInfo(user.accessibleApps);
		return new ModelAndFragment(FRAG_APP_LIST, ImmutableMap.of("owned", apps, "shared", apps_shared));
	}

	@Prioritize
	@GetMapping("/userHome")
	public ModelAndView createUserHome() {
		try {
			return MVCUtils.wrapAuthenticatedHomePage("Applications List", "Click on a link to access the corresponding application.",
					createAppList(), userController.createProgressList(), userController.createFileList());
		} catch (Exception e) {
			logger.error("Failed to create userHome. ", e);
			return MVCUtils.errorMV("Failed to create homepage. ");
		}
	}

	@Prioritize
	@GetMapping("/userProgress")
	public ModelAndView createProgressList() {
		try {
			return MVCUtils.wrapAuthenticatedHomePage("Job Details",
					"Job details can also be found on your user home page.", userController.createProgressList());
		} catch (Exception e) {
			logger.error("Failed to create userHome. ", e);
			return MVCUtils.errorMV("Failed to create homepage. ");
		}
	}

	@Prioritize
	@GetMapping("/userFiles")
	public ModelAndView createFileList() {
		try {
			return MVCUtils.wrapAuthenticatedHomePage("File Details",
					"File details can also be found under your user home page.", userController.createFileList());
		} catch (Exception e) {
			logger.error("Failed to create userHome. ", e);
			return MVCUtils.errorMV("Failed to create homepage. ");
		}
	}

	@Prioritize
	@GetMapping("/JobProgress")
	public @ResponseBody Map<String, Object> getJobProgress(@ModelAttribute("task") final String task,
			@ModelAttribute("indexes") final String indexes, BindingResult result) {
		try {
			if (result.hasErrors()) {
				return ImmutableMap.of("error", "Invalid param for querying job progress.");
			}
			LocalJobProgress progress = platform.getJobProgress(task);
			int[] inds = Arrays.stream(indexes.replaceAll("[\\[\\]]", "").split(","))
					.mapToInt(ind -> Integer.parseInt(ind)).toArray();
			if (progress == null)
				return ImmutableMap.of("error", "Not found.");
			return ImmutableMap.of("progress", progress.toWrapper(inds, -1));
		} catch (Exception e) {
			logger.error("Failed to create userHome. ", e);
			return ImmutableMap.of("error", "Failed to get job progress. Internal error.");
		}
	}

	@Prioritize
	@RequestMapping(value = "/del_file", method = RequestMethod.POST)
	@ResponseBody
	public final Map<String, Object> delete(@RequestParam("fileName") String fileName) {
		try {
			FileServingUtils.dropFile(fileName);
			return ImmutableMap.of();
		} catch (Exception e) {
			logger.error("Failed delete application.", e);
			return ImmutableMap.of("error", "Failed to delete the file.");
		}
	}

	@Prioritize
	@RequestMapping(value = "/rn_file", method = RequestMethod.POST)
	@ResponseBody
	public final Map<String, Object> rename(@RequestParam("value") String value,
			@RequestParam("old_value") String old_value) {
		try {
			FileServingUtils.renameFile(old_value, value);
			return ImmutableMap.of();
		} catch (Exception e) {
			logger.error("Failed delete application.", e);
			return ImmutableMap.of("error", "Failed to rename the file. " + e.getMessage());
		}
	}

	/***
	 * Abstract binding for the ApplicationInfo class. The configuration class is
	 * abstract, we need to figure out the correct class by using the application
	 * type.
	 * 
	 * @param webDataBinder
	 * @param servletRequest
	 */
	@InitBinder
	public void initBinder(WebDataBinder webDataBinder, HttpServletRequest servletRequest) {

		if (!"POST".equalsIgnoreCase(servletRequest.getMethod())) {
			return;
		}

		Object nonCastedTarget = webDataBinder.getTarget();
		if (nonCastedTarget == null || !(nonCastedTarget instanceof ApplicationInfo)) {
			return;
		}

		ApplicationInfo target = (ApplicationInfo) nonCastedTarget;
		try {
			String type = servletRequest.getParameter("applicationType");
			Class<? extends ApplicationConfiguration> conf_cls = AppPlatform.appTypes.get(type);
			ApplicationConfiguration conf = conf_cls.newInstance();
			target.configuration = conf;
		} catch (Exception e) {
			AppPlatform.logger.error("Invalid aplication type " + target.applicationType, e);
		}
	}

}