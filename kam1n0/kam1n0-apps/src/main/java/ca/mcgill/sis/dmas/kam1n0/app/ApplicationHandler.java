package ca.mcgill.sis.dmas.kam1n0.app;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import ca.mcgill.sis.dmas.kam1n0.app.adata.BlockDataUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import com.google.common.collect.ImmutableMap;
import com.sun.mail.imap.AppendUID;

import ca.mcgill.sis.dmas.kam1n0.AppController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform;
import ca.mcgill.sis.dmas.kam1n0.UserController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.Prioritize;
import ca.mcgill.sis.dmas.kam1n0.app.adata.BinaryDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionCommentWrapper;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserInfo;
import ca.mcgill.sis.dmas.kam1n0.app.util.MVCUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.ModelAndFragment;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Comment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

/**
 * All the APP services follow path:
 *
 * \/app_type\/app_id\/other_request...
 *
 */
public abstract class ApplicationHandler {

	protected ApplicationMeta meta = null;
	private static Logger logger = LoggerFactory.getLogger(ApplicationHandler.class);

	public ApplicationHandler(ApplicationMeta meta) {
		this.meta = meta;
	}

	@Autowired
	protected AppController controller;

	@Autowired
	protected UserController userController;

	@Autowired
	public ApplicationInfoValidatorUpdated validator;

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public final static String FRAG_APP_PLUG = "apps/app_plugin";
	public final static String FRAG_APP_TITLE = "apps/app_title";
	public final static String FRAG_APP_BIN_LIST = "apps/app_binary_list";
	public final static String FRAG_APP_FUNC_FLOW = "apps/app_func_flow";
	public final static String FRAG_APP_FUNC_TEXT = "apps/app_func_text";
	public final static String FRAG_APP_BIN_DEL = "apps/delete_bin";

	public ModelAndView getHomeModelAndViewImpl(long appId) {
		ApplicationInfoSummary summary = meta.getInfoSummary(appId);
		return MVCUtils.wrapAuthenticatedHomePage(summary.basicInfo.applicationType + '/',
				Long.toString(summary.basicInfo.appId), getAppTileFragment(summary),
				getBinaryListFragment(summary.basicInfo));
	}

	public final ModelAndFragment getAppTileFragment(ApplicationInfoSummary summary) {
		return new ModelAndFragment(FRAG_APP_TITLE, summary);
	}

	public final ModelAndFragment getBinaryListFragment(ApplicationInfo info) {
		return new ModelAndFragment(FRAG_APP_BIN_LIST, info);
	}
	public List<Binary> getBinaries(long appId) {
		return meta.getBinaries(appId);
	}

	public List<Function> getFunctions(long appId, long binaryId) {
		return meta.getFunctions(appId, binaryId);
	}

	public final static String getHomePath(String appType, long appId) {
		if (!appType.startsWith("/"))
			appType = "/" + appType;
		return appType + "/" + Long.toString(appId) + "/home";
	}

	public final static String getPrefixPath(String appType, long appId) {
		if (!appType.startsWith("/"))
			appType = "/" + appType;
		return appType + "/" + Long.toString(appId) + "/";
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/", method = RequestMethod.GET)
	public final ModelAndView getAppPluginHome(@PathVariable("appId") long appId) {
		ApplicationInfoSummary summary = meta.getInfoSummary(appId);
		return MVCUtils.wrapAuthenticatedHomePage(summary.basicInfo.applicationType + '/',
				Long.toString(summary.basicInfo.appId), new ModelAndFragment(FRAG_APP_PLUG, summary));
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/home", method = RequestMethod.GET)
	public final ModelAndView getHomeModelAndView(@PathVariable("appId") long appId) {
		return getHomeModelAndViewImpl(appId);
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/info", method = RequestMethod.GET)
	@ResponseBody
	public final ApplicationInfo getApplicationInfo(@PathVariable("appId") long appId) {
		return this.meta.getInfo(appId);
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_info", method = RequestMethod.GET)
	@ResponseBody
	public final List<FunctionDataUnit> getFunctionInfos(@PathVariable("appId") long appId,
			@RequestParam("id") long binaryId) {
		return this.meta.getFunctions(appId, binaryId).stream().map(func -> new FunctionDataUnit(func, true))
				.collect(Collectors.toList());
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/bin_info", method = RequestMethod.GET)
	@ResponseBody
	public final List<BinaryDataUnit> getBinInfos(@PathVariable("appId") long appId) {
		return this.getBinaries(appId).stream().map(BinaryDataUnit::new).collect(Collectors.toList());
	}



	@Prioritize
	@RequestMapping(value = "/{appId:.+}/delBin", method = RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> delCluster(@PathVariable("appId") long appId, @RequestParam("id") long binaryId, Model model) {
		try {
			BinaryDataUnit bin = new BinaryDataUnit(this.meta.getBinary(appId, binaryId));
			this.meta.getFunctions(appId, binaryId).stream().map(func -> this.meta.getFunction(appId,func.functionId)).forEach(func -> {func.nodes.stream().forEach(blk->{this.meta.delBlock(appId,Long.parseLong(blk.blockID));});});
			this.meta.getFunctions(appId, binaryId).stream().forEach(func -> this.meta.delFunction(appId,func.functionId));
			this.meta.delBinary(appId,binaryId);
			return ImmutableMap.of();

		} catch (Exception e) {
			logger.error("Failed to delete the binary file.", e);
			return ImmutableMap.of("error", "Failed to delete the binary file.");
		}
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_flow", method = RequestMethod.GET)
	@ResponseBody
	public final FunctionDataUnit getFunctionFlow(@PathVariable("appId") long appId,
			@RequestParam("id") long functionId) {
		return this.meta.getFunction(appId, functionId);
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_flow_show", method = RequestMethod.GET)
	public final ModelAndView showFunctionFlow(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(FRAG_APP_FUNC_FLOW, summary));
		} catch (Exception e) {
			logger.error("Failed creating func flow view.", e);
			return errorMV(e.getMessage());
		}
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_text_show", method = RequestMethod.GET)
	public final ModelAndView showFunctionText(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(FRAG_APP_FUNC_TEXT, summary));
		} catch (Exception e) {
			logger.error("Failed creating func flow view.", e);
			return errorMV(e.getMessage());
		}
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_comment", method = RequestMethod.GET)
	@ResponseBody
	public final List<FunctionCommentWrapper> getComment(@PathVariable("appId") long appId,
			@RequestParam("fid") long functionId) {
		try {
			List<FunctionCommentWrapper> comments = meta.getComment(appId, functionId);
			return comments;
		} catch (Exception e) {
			logger.error("Failed get commnet.", e);
			return null;
		}
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_comment", method = RequestMethod.POST)
	@ResponseBody
	public final Map<String, Object> putComment(@PathVariable("appId") long appId,
			@RequestParam("functionId") long functionId, @RequestParam("functionOffset") String functionOffset,
			@RequestParam("date") String date, @RequestParam("comment") String content) {
		try {

			if (content.length() > 0 && !meta.checkFunc(appId, functionId)) {
				return ImmutableMap.of("error", "The function for your comment is not in this repository.");
			}

			Comment comment = new Comment();
			comment.functionId = functionId;
			comment.functionOffset = functionOffset.trim();
			if (date.trim().length() > 0)
				comment.date = Long.parseLong(date.trim());
			else
				comment.date = new Date().getTime();
			comment.comment = content;
			comment.userName = UserController.findUserName();
			meta.putComment(appId, comment);
			return ImmutableMap.of("result", comment);
		} catch (Exception e) {
			logger.error("Failed put commnet.", e);
			return ImmutableMap.of("error", "Failed to update the comment.");
		}
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/arch_rest", method = RequestMethod.GET)
	@ResponseBody
	public final AsmLineNormalizationResource getArchitectureResources(@RequestParam("arch") ArchitectureType arch) {
		return AsmLineNormalizationResource.retrieve(arch);
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/del", method = RequestMethod.POST)
	@ResponseBody
	public final Map<String, Object> delete(@PathVariable("appId") long appId, String appName, String pwd) {
		try {
			UserInfo info = UserController.findUser();
			if (!bCryptPasswordEncoder.matches(pwd, info.credential))
				return ImmutableMap.of("error", "You entered the wrong password. Please retry.");
			ApplicationInfo appInfo = getApplicationInfo(appId);
			if (appInfo == null)
				return ImmutableMap.of("error", "The application that you are trying to delete is non-existed.");
			if (!appInfo.name.equals(appName))
				return ImmutableMap.of("error", "You entered the wrong application name. Please retry.");
			meta.delete(appId);
			Set<String> all_old = Stream.concat(appInfo.users_read.stream(), appInfo.users_wirte.stream())
					.collect(Collectors.toSet());
			userController.removeAccessibleApp(appId, all_old);
			return ImmutableMap.of();
		} catch (Exception e) {
			logger.error("Failed delete application.", e);
			return ImmutableMap.of("error", "Failed to delete the application.");
		}
	}

	@Prioritize
	@GetMapping("/{appId:.+}/editApp")
	public ModelAndView showApplicationFormEdit(@PathVariable("appId") long appId, Model model) {
		try {
			ApplicationInfo info = getApplicationInfo(appId);
			model.addAttribute("confObj", info);
			model.addAttribute("applicationTypes", AppPlatform.appTypes.keySet());
			model.addAttribute("appConfForm", info.configuration.createView());
			model.addAttribute("edit", true);
			return MVCUtils.wrapAuthenticatedHomePage("Edit the Application.", "Please edit the required information.",
					new ModelAndFragment(AppController.FRAG_APP_CONF, model));
		} catch (Exception e) {
			logger.error("Failed to create application form..", e);
			return MVCUtils.errorMV("Failed to create application form.");
		}
	}

	@Prioritize
	@PostMapping("/{appId:.+}/editApp")
	public ModelAndView submitApplicationFormEdit(@PathVariable("appId") long appId,
			@RequestParam(value = "reads", defaultValue = "") List<String> reads,
			@RequestParam(value = "writes", defaultValue = "") List<String> writes,
			@ModelAttribute("confObj") final ApplicationInfo info, BindingResult bindingResult, Model model) {
		try {
			validator.validate(info, bindingResult);
			if (bindingResult.hasErrors()) {
				if (info.configuration != null)
					model.addAttribute("appConfForm", info.configuration.createView());
				model.addAttribute("confObj", info);
				model.addAttribute("applicationTypes", AppPlatform.appTypes.keySet());
				model.addAttribute("edit", true);
				return MVCUtils.wrapAuthenticatedHomePage("Edit an application.", "Please edit the following errors.",
						new ModelAndFragment(AppController.FRAG_APP_CONF, model));
			}
			ApplicationInfo oldInfo = getApplicationInfo(appId);
			if (oldInfo == null) {
				logger.error("A user is trying to update an non-existed app. {} {}", UserController.findUser(), appId);
				return MVCUtils.errorMV("Error", "The app you are trying to update is non-existed.");
			}
			info.users_wirte = writes.stream().filter(val -> val.trim().length() > 0)
					.collect(Collectors.toCollection(HashSet::new));
			info.users_read = reads.stream().filter(val -> val.trim().length() > 0)
					.collect(Collectors.toCollection(HashSet::new));
			info.users_read.removeAll(info.users_wirte);
			controller.updateApplicationInstance(info);
			model.addAttribute("edit", true);

			Set<String> all_old = Stream.concat(oldInfo.users_read.stream(), oldInfo.users_wirte.stream())
					.collect(Collectors.toSet());
			userController.removeAccessibleApp(appId, all_old);
			Set<String> all_new = Stream.concat(info.users_read.stream(), info.users_wirte.stream())
					.collect(Collectors.toSet());
			userController.addAccessibleApp(appId, all_new);

			return MVCUtils.redirectMV("/userHome");
		} catch (Exception e) {
			logger.error("Failed to create application.", e);
			return MVCUtils.errorMV("Failed to create application {}", e.getMessage());
		}
	}

	public final static ModelAndView errorMV(String message, Object... param) {
		return MVCUtils.errorMV(message, param);
	}

	public final static ModelAndView succeedMV(String message, Object... param) {
		return MVCUtils.succeedMV(message, param);
	}

	@InitBinder
	public void initBinder(WebDataBinder webDataBinder, HttpServletRequest servletRequest) {
		controller.initBinder(webDataBinder, servletRequest);
	}

}
