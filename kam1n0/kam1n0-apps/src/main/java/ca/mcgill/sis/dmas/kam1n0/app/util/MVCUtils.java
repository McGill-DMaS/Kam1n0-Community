package ca.mcgill.sis.dmas.kam1n0.app.util;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.AppController;
import ca.mcgill.sis.dmas.kam1n0.UserController;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationHandler;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserEntity;
import ca.mcgill.sis.dmas.kam1n0.app.user.UserInfo;

public class MVCUtils {

	public final static String VIEW_HOME_AU = "HomeAuthenticatedv2";
	public final static String VIEW_HOME_RED = "HomeRenderer";
	public final static String VIEW_HOME_UAU = "HomeUnauthenticated";
	public final static String FRAG_ERROR_MSG = "msg_error";
	public final static String FRAG_SUCED_MSG = "msg_succeed";

	public final static ModelAndView errorMV(String message, Object... param) {
		ModelAndView mv = new ModelAndView();
		mv.addObject("message", StringResources.parse(message, param));
		mv.setViewName(FRAG_ERROR_MSG);
		return mv;
	}

	public final static ModelAndView succeedMV(String message, Object... param) {
		ModelAndView mv = new ModelAndView();
		mv.addObject("message", StringResources.parse(message, param));
		mv.setViewName(FRAG_SUCED_MSG);
		return mv;
	}

	public final static ModelAndView redirectMV(String redictPath) {
		ModelAndView mv = new ModelAndView();
		mv.setViewName("redirect:" + redictPath);
		return mv;
	}

	public final static ModelAndView wrapAuthenticatedHomePage(String title, String summary,
			ModelAndFragment... views) {
		return wrapAuthenticatedHomePage(title, summary, Arrays.asList(views));
	}

	public final static ModelAndView wrapAuthenticatedHomePage(String title, String summary,
			List<ModelAndFragment> views) {
		UserInfo user = UserController.findUser();
		ModelAndView mv = new ModelAndView();
		mv.addObject("home_title", title);
		mv.addObject("home_summary", summary);
		mv.addObject("views", new ArrayList<>(views));
		mv.addObject("user", user);
		mv.setViewName(VIEW_HOME_AU);
		return mv;
	}

	public final static ModelAndView wrapAuthenticatedRenderer(ModelAndFragment... views) {
		return wrapAuthenticatedRenderer(Arrays.asList(views));
	}

	public final static ModelAndView wrapAuthenticatedRenderer(List<ModelAndFragment> views) {
		UserInfo user = UserController.findUser();
		ModelAndView mv = new ModelAndView();
		mv.addObject("views", new ArrayList<>(views));
		mv.addObject("user", user);
		mv.setViewName(VIEW_HOME_RED);
		return mv;
	}

	public final static ModelAndView wrapUnauthenticatedHomePage(ModelAndFragment... views) {
		ModelAndView mv = new ModelAndView();
		mv.addObject("views", new ArrayList<>(Arrays.asList(views)));
		mv.setViewName(VIEW_HOME_UAU);
		return mv;
	}

	public static Model fillModel(Model model, Object obj) throws Exception {
		for (Field field : obj.getClass().getDeclaredFields()) {
			field.setAccessible(true);
			if (!model.containsAttribute(field.getName()))
				model.addAttribute(field.getName(), field.get(obj));
		}
		return model;
	}

}
