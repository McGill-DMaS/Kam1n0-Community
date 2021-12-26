package ca.mcgill.sis.dmas.kam1n0;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.Prioritize;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobInfo;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserFactory;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserInfo;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserInfoValidator;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserInfoWrapper;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileInfo;
import ca.mcgill.sis.dmas.kam1n0.app.util.MVCUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.ModelAndFragment;

@Controller
public class UserController {

	static Logger logger = LoggerFactory.getLogger(UserController.class);

	public static UserInfo findUser() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return ((UserInfoWrapper) auth.getPrincipal()).entity;
	}

	public static String findUserName() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return auth.getName();
	}

	public List<UserInfo> findUser(Collection<String> names) {
		return factory.findUser(names);
	}

	public void updateUser(UserInfo user) {
		factory.update(user);
	}

	public void addApp(Long appId, String name) {
		UserInfo userInfo = UserController.findUser();
		userInfo.ownedApps.add(appId);
		factory.save(userInfo);
	}

	public void dropApp(Long appId) {
		UserInfo userInfo = UserController.findUser();
		userInfo.ownedApps.remove(appId);
		factory.save(userInfo);
	}

	public void removeAccessibleApp(long appId, Collection<String> userNames) {
		List<UserInfo> users = findUser(userNames);
		users.parallelStream().forEach(user -> {
			user.accessibleApps.remove(appId);
			updateUser(user);
		});
	}

	public void addAccessibleApp(long appId, Collection<String> userNames) {
		List<UserInfo> users = findUser(userNames);
		users.parallelStream().forEach(user -> {
			user.accessibleApps.add(appId);
			updateUser(user);
		});
	}

	@Autowired
	UserFactory factory;

	@Autowired
	UserInfoValidator validator;

	@Autowired
	GlobalResources res;

	private static final String FRAG_JOBS = "users/jobs";
	private static final String FRAG_FILES = "users/files";

	@Prioritize
	@GetMapping("/login")
	public ModelAndView login(Model model, String error, String logout) {
		if (error != null)
			model.addAttribute("error", "Your username and password is invalid.");

		if (logout != null)
			model.addAttribute("logout", "You have been logged out successfully.");

		return MVCUtils.wrapUnauthenticatedHomePage(new ModelAndFragment("users/login", model));
	}

	@Prioritize
	@GetMapping("/register")
	public ModelAndView registration(Model model) {
		model.addAttribute("user", new UserInfo());
		return MVCUtils.wrapUnauthenticatedHomePage(new ModelAndFragment("users/register", model));
	}

	@Prioritize
	@PostMapping("/register")
	public ModelAndView registration(@ModelAttribute("user") UserInfo userForm, BindingResult bindingResult,
			Model model) {
		validator.validate(userForm, bindingResult);

		if (bindingResult.hasErrors()) {
			return MVCUtils.wrapUnauthenticatedHomePage(new ModelAndFragment("users/register", model));
		}

		factory.add(userForm);
		return new ModelAndView("redirect:/login?new");
	}

	@Prioritize
	@GetMapping("/validate")
	public @ResponseBody String validateSession(Model model) {
		return "";
	}

	public ModelAndFragment createProgressList() {
		List<LocalDmasJobInfo> jobs = res.scheduler.listJobs(UserController.findUserName());
		return new ModelAndFragment(FRAG_JOBS, jobs);
	}

	public ModelAndFragment createFileList() {
		File userFolder = new File(Environment.getUserFolder(findUserName()));
		List<FileInfo> files = Arrays.stream(userFolder.listFiles()).filter(file->file.isFile()).map(FileInfo::readFileInfo)
				.filter(info -> info != null).collect(Collectors.toList());

		Collections.sort(files, Collections.reverseOrder());
		return new ModelAndFragment(FRAG_FILES, files);
	}
}
