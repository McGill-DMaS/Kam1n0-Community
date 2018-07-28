package ca.mcgill.sis.dmas.kam1n0.app.clone.symbolic;

import java.util.Arrays;
import java.util.List;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.Access;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AccessMode;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.Prioritize;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfoSummary;
import ca.mcgill.sis.dmas.kam1n0.app.clone.AbastractCloneSearchHandler;
import ca.mcgill.sis.dmas.kam1n0.app.util.MVCUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.ModelAndFragment;

@Controller
@RequestMapping(Sym1n0ApplicationMeta.appType)
@AppType(Sym1n0ApplicationMeta.appType)
public class Sym1n0ApplicationHandler extends AbastractCloneSearchHandler {

	private static Logger logger = LoggerFactory.getLogger(Sym1n0ApplicationHandler.class);

	public final static String VIEW_CLONE_FUNC = "apps/clone/sym1n0-clone/app_func_clone_render";
	public final static String VIEW_CLONE_FUNC_QUERY = "apps/clone/sym1n0-clone/app_request_func_query";
	public final static String VIEW_CLONE_FUNC_DIFF_FLOW_LOGIC = "apps/clone/sym1n0-clone/app_func_diff_graph_logic";

	@Autowired
	public Sym1n0ApplicationHandler(Sym1n0ApplicationMeta meta) {
		super(meta);
	}

	@Override
	public List<String> getExamples() {
		return Arrays.asList("adler32-arm-binary.txt");
	}

	@Override
	public String getFunctionQueryFragment() {
		return VIEW_CLONE_FUNC_QUERY;
	}

	@Override
	public String getFuncCloneRenderFragment() {
		return VIEW_CLONE_FUNC;
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_flow_logic_show", method = RequestMethod.GET)
	@Access(AccessMode.READ)
	public final ModelAndView showFunctionLogicFlow(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(FRAG_APP_FUNC_FLOW, summary));
		} catch (Exception e) {
			logger.error("Failed creating func flow view.", e);
			return errorMV(e.getMessage());
		}
	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_diff_flow_logic", method = RequestMethod.GET)
	@Access(AccessMode.READ)
	public final ModelAndView showFunctionDiffLogicFlow(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_FUNC_DIFF_FLOW_LOGIC, summary));
		} catch (Exception e) {
			logger.error("Failed creating func diffe view.", e);
			return errorMV(e.getMessage());
		}

	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_diff_flow_vex", method = RequestMethod.GET)
	@Access(AccessMode.READ)
	public final ModelAndView showFunctionDiffVexFlow(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			summary.appAttrs.put("code_key", "vex");
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_FUNC_DIFF_FLOW, summary));
		} catch (Exception e) {
			logger.error("Failed creating func diffe view.", e);
			return errorMV(e.getMessage());
		}

	}

	@Prioritize
	@RequestMapping(value = "/{appId:.+}/func_diff_text_vex", method = RequestMethod.GET)
	@Access(AccessMode.READ)
	public final ModelAndView showFunctionDiffVexText(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			summary.appAttrs.put("code_key", "vex");
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_FUNC_DIFF_TEXT, summary));
		} catch (Exception e) {
			logger.error("Failed creating func diffe view.", e);
			return errorMV(e.getMessage());
		}

	}

}
