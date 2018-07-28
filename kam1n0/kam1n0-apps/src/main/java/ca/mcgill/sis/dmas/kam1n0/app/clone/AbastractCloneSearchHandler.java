package ca.mcgill.sis.dmas.kam1n0.app.clone;

import java.io.File;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.Access;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AccessMode;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationHandler;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfoSummary;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDetectionResultForWeb;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileServingUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.MVCUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.ModelAndFragment;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;

public abstract class AbastractCloneSearchHandler extends ApplicationHandler {

	private static Logger logger = LoggerFactory.getLogger(AbastractCloneSearchHandler.class);

	public AbastractCloneSearchHandler(ApplicationMeta meta) {
		super(meta);
	}

	public final static String VIEW_CLONE_REQUEST = "apps/clone/app_request";
	public final static String VIEW_CLONE_REQUEST_FUNC_SEARCH = "apps/clone/app_request_func_query";
	public final static String VIEW_CLONE_REQUEST_BIN_INDEX = "apps/clone/app_request_bin_index";
	public final static String VIEW_CLONE_SEARCH = "apps/clone/app_func_clone_search";
	public final static String VIEW_CLONE_COMPOSITION = "apps/clone/app_composition";

	public final static String VIEW_CLONE_FUNC_DIFF_TEXT = "apps/clone/app_func_diff_text";
	public final static String VIEW_CLONE_FUNC_DIFF_TEXT_GROUP = "apps/clone/app_func_diff_text_group";
	public final static String VIEW_CLONE_FUNC_DIFF_FLOW = "apps/clone/app_func_diff_graph";

	public final static String VIEW_CLONE_BIN = "apps/clone/app_bin_composition";

	public abstract List<String> getExamples();

	public abstract String getFuncCloneRenderFragment();

	public String getFunctionQueryFragment() {
		return VIEW_CLONE_REQUEST_FUNC_SEARCH;
	}

	public String getBinIndexFragment() {
		return VIEW_CLONE_REQUEST_BIN_INDEX;
	}

	@Override
	public ModelAndView getHomeModelAndViewImpl(long appId) {
		ApplicationInfoSummary summary = meta.getInfoSummary(appId);
		ModelAndFragment title = getAppTileFragment(summary);
		ModelAndFragment binaryList = getBinaryListFragment(summary.basicInfo);
		ModelAndFragment request = new ModelAndFragment(VIEW_CLONE_REQUEST, //
				ImmutableMap.of(//
						"summary", summary, //
						"queryFragment", getFunctionQueryFragment(), //
						"queryModel", ImmutableMap.of(//
								"summary", summary, //
								"examples", getExamples()), //
						"indexFragment", getBinIndexFragment(), //
						"indexModel", ImmutableMap.of(//
								"summary", summary //
						))//
		);
		return MVCUtils.wrapAuthenticatedHomePage(summary.basicInfo.applicationType + '/',
				Long.toString(summary.basicInfo.appId), title, binaryList, request);
	}

	@RequestMapping(value = "/{appId:.+}/push_bin", method = RequestMethod.POST)
	public final @ResponseBody Map<String, Object> postBinary(@PathVariable("appId") long appId,
			@RequestParam("files") Object[] objs) {
		ArrayList<Object> nobjs = new ArrayList<>();
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String name = auth.getName();
		String tmpDir = Environment.getUserTmpDir(name);
		for (int i = 0; i < objs.length; ++i) {
			if (objs[i] instanceof MultipartFile) {
				MultipartFile file = ((MultipartFile) objs[i]);
				File new_file = new File(tmpDir + "/" + file.getOriginalFilename());
				new_file.getParentFile().mkdirs();
				try {
					file.transferTo(new_file);
				} catch (Exception e) {
					logger.error("Failed to process submited mutipart file", e);
					return ImmutableMap.of("error", "Upload failes. Please check server log.");
				}
				nobjs.add(new_file);
			} else if (objs[i] instanceof String) {
				if (((String) objs[i]).trim().length() < 1)
					continue;
				BinarySurrogate surrogate;
				try {
					surrogate = BinarySurrogate.loadFromJson((String) objs[i]);
					surrogate.processRawBinarySurrogate();
					nobjs.add(surrogate);
				} catch (Exception e) {
					logger.error("Failed to process submited mutipart file", e);
					return ImmutableMap.of("error", "Upload failes. Please check app log.");
				}
			} else {
				logger.error("Unsupported type {}", objs[i].getClass().getName());
				return ImmutableMap.of("error", "Unsupported type. Please check app log.");
			}
		}
		// if things to be indexed is very small. We index them right now.
		// Otherwise we create a running job.
		if (nobjs.size() == 1 && nobjs.get(0) instanceof BinarySurrogate
				&& ((BinarySurrogate) nobjs.get(0)).functions.size() < 10) {
			CloneSearchResources res = meta.getResource(appId);
			try {
				res.indexBinary(appId, (BinarySurrogate) nobjs.get(0), new LocalJobProgress());
			} catch (Exception e) {
				logger.error("Failed to index.", e);
				return ImmutableMap.of("error", "Failed to index.");
			}
			return ImmutableMap.of();
		} else {
			try {
				Map<String, Object> params = new HashMap<String, Object>();
				params.put(BinaryIndexProcedureLSHMR.KEY_FILES, nobjs);
				ApplicationInfo appInfo = meta.getInfo(appId);
				String idstr = this.meta.submitJob(appId, meta.getAppType(), appInfo.name, name,
						BinaryIndexProcedureLSHMR.class, params);
				return ImmutableMap.of("jid", idstr);
			} catch (Exception e) {
				return ImmutableMap.of("error", e.getMessage());
			}
		}
	}

	@RequestMapping(value = "/{appId:.+}/search_bin", method = RequestMethod.POST)
	@Access(AccessMode.READ)
	public final @ResponseBody Map<String, Object> searchBinary(@PathVariable("appId") long appId,
			@RequestParam(value = "threshold", defaultValue = "0.5") double threshold,
			@RequestParam(value = "avoidSameBinary") final boolean avoidSameBinary,
			@RequestParam(value = "topk", defaultValue = "15") int topk, //
			@RequestParam(value = "bin") Object obj) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String name = auth.getName();
		String tmpDir = Environment.getUserTmpDir(name);
		if (obj instanceof MultipartFile) {
			MultipartFile file = ((MultipartFile) obj);
			File new_file = new File(tmpDir + "/" + file.getOriginalFilename());
			try {
				new_file.getParentFile().mkdirs();
				file.transferTo(new_file);
			} catch (Exception e) {
				logger.error("Failed to process submited mutipart file", e);
				return ImmutableMap.of("error", "Unsupported format " + obj.getClass().getName());
			}
			obj = new_file;
		} else if (obj instanceof String) {
			BinarySurrogate surrogate;
			try {
				surrogate = BinarySurrogate.loadFromJson((String) obj);
				surrogate.processRawBinarySurrogate();
				obj = surrogate;
			} catch (Exception e) {
				logger.error("Failed to process submited mutipart file", e);
				return ImmutableMap.of("error", "Upload failes. Please check server log. " + obj.getClass().getName());
			}
		} else {
			logger.error("Unsupported type {}", obj.getClass().getName());
			return ImmutableMap.of("error", "Upload failes. Please check server log." + obj.getClass().getName());
		}

		Map<String, Object> params = new HashMap<String, Object>();
		params.put(BinaryAnalysisProcedureCompositionAnalysis.KEY_FILE, obj);
		params.put(BinaryAnalysisProcedureCompositionAnalysis.KEY_THRESHOLD, threshold);
		params.put(BinaryAnalysisProcedureCompositionAnalysis.KEY_FILTER, avoidSameBinary);
		params.put(BinaryAnalysisProcedureCompositionAnalysis.KEY_TOP, topk);
		try {
			ApplicationInfo appInfo = meta.getInfo(appId);
			String id = this.meta.submitJob(appId, meta.getAppType(), appInfo.name, name,
					BinaryAnalysisProcedureCompositionAnalysis.class, params);
			return ImmutableMap.of("jid", id);
		} catch (Exception e) {
			logger.error("Failed submitting job.", e);
			return ImmutableMap.of("error", e.getMessage());
		}

	}

	@RequestMapping(value = "/{appId:.+}/BinaryComposition", method = RequestMethod.GET)
	@Access(AccessMode.READ)
	public final ModelAndView searchBinaryRenderer(@PathVariable("appId") long appId) {
		return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_BIN, meta.getInfo(appId)));
	}

	@RequestMapping(value = "/{appId:.+}/BinaryComposition", method = RequestMethod.POST)
	@Access(AccessMode.READ)
	public final @ResponseBody Map<String, Object> searchBinaryRenderer(@PathVariable("appId") long appId,
			@RequestParam("fileName") String fileName,
			@RequestParam(value = "keyword", defaultValue = "*") String keyword, HttpServletRequest request) {

		try {
			String cloneDetail = request.getParameter("cloneDetail");
			String list = request.getParameter("list");
			String addRange = request.getParameter("addRange");
			String summary = request.getParameter("summary");
			String[] not_selected = request.getParameterValues("not_selected[]");
			// int addrRange = 200000; depreciated.

			fileName = URLDecoder.decode(fileName, "UTF-8");
			BinarySearchUnit servingObj = FileServingUtils.getFileRelatedObject(fileName, BinarySearchUnit.class);

			if (cloneDetail != null) {
				FunctionCloneDetectionResultForWeb result = servingObj.getCloneDetail(cloneDetail);
				FunctionCloneDataUnit unit = new FunctionCloneDataUnit(Lists.newArrayList(result));
				unit.generateCloneGraph();
				return ImmutableMap.of("object", unit);
			}

			if (list != null) {
				long addrStart = NumberUtils.toLong(request.getParameter("addrStart"), 0);
				long addrEnd = NumberUtils.toLong(request.getParameter("addrEnd"), Long.MAX_VALUE);
				return ImmutableMap.of("object",
						servingObj.getCloneInfoList(addrStart, addrEnd, not_selected, keyword));
			}

			if (addRange != null) {
				return ImmutableMap.of("object", servingObj.getAddressRanges());
			}

			if (summary != null) {
				return ImmutableMap.of("object", servingObj.summarize());
			}
		} catch (Exception e) {
			logger.error("Failed to process query.", e);
		}
		return ImmutableMap.of("error", "Unacceptable request.");

	}

	@RequestMapping(value = "/{appId:.+}/search_func", method = RequestMethod.POST)
	@Access(AccessMode.READ)
	public final ModelAndView searchFunctionPage(@PathVariable("appId") long appId,
			@RequestParam(value = "threshold", defaultValue = "-1") double threshold,
			@RequestParam(value = "topk", defaultValue = "15") int topk) {
		Map<String, Object> model = new HashMap<>();
		model.put("threshold", threshold);
		model.put("topk", topk);
		ApplicationInfo info = meta.getInfo(appId);
		model.put("query_url", info.applicationType + "/" + info.appId + "/search_func_rest");
		model.put("render_url", info.applicationType + "/" + info.appId + "/search_func_render");
		return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_SEARCH, model));
	}

	@RequestMapping(value = "/{appId:.+}/search_func_render", method = RequestMethod.GET)
	public final ModelAndView searchFunctionPage() {
		return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(getFuncCloneRenderFragment(), ""));
	}

	@RequestMapping(value = "/{appId:.+}/search_func_rest", method = RequestMethod.POST)
	@Access(AccessMode.READ)
	public final @ResponseBody Map<String, Object> searchFunctionRest(@PathVariable("appId") long appId,
			@RequestParam(value = "threshold", defaultValue = "-1") double threshold,
			@RequestParam(value = "topk", defaultValue = "15") int topk, //
			@RequestParam(value = "func") String str,
			@RequestParam(value = "avoidSameBinary", defaultValue = "false") boolean avoidSameBinary,
			HttpServletRequest request) {
		Binary binary;
		CloneSearchResources res = meta.getResource(appId);
		try {
			BinarySurrogate surrogate = BinarySurrogate.loadFromJson(str);
			surrogate.processRawBinarySurrogate();
			binary = surrogate.toBinary();
		} catch (Exception e) {
			// treat as raw text:
			String time = StringResources.timeString();
			try {
				binary = res.parser.fromPlainText(//
						Arrays.asList(str.split("\n")), //
						"func-" + time, //
						"bin" + time, //
						request.getParameterMap());
			} catch (Exception e1) {
				logger.error("Failed to process raw input. " + str, e1);
				return ImmutableMap.of("error", "Failed to process raw input. " + e1.getMessage());
			}
		}

		try {
			FunctionCloneDataUnit du = res.detectFunctionClone(appId, binary.functions.get(0), threshold, topk,
					avoidSameBinary, true);
			return ImmutableMap.of("result", du);
		} catch (Exception e) {
			logger.error("Failed detecting clone.", e);
			return ImmutableMap.of("error", "Failed to detect clone. " + e.getMessage());
		}
	}

	@RequestMapping(value = "/{appId:.+}/func_diff_flow", method = RequestMethod.GET)
	public final ModelAndView diffFuncFlow(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_FUNC_DIFF_FLOW, summary));
		} catch (Exception e) {
			logger.error("Failed creating func diffe view.", e);
			return errorMV(e.getMessage());
		}
	}

	@RequestMapping(value = "/{appId:.+}/func_diff_text", method = RequestMethod.GET)
	public final ModelAndView diffFuncText(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_FUNC_DIFF_TEXT, summary));
		} catch (Exception e) {
			logger.error("Failed creating func diff view.", e);
			return errorMV(e.getMessage());
		}
	}

	@RequestMapping(value = "/{appId:.+}/func_diff_text_group", method = RequestMethod.GET)
	public final ModelAndView diffFuncTextGroup(@PathVariable("appId") long appId) {
		try {
			ApplicationInfoSummary summary = meta.getInfoSummary(appId);
			return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_CLONE_FUNC_DIFF_TEXT_GROUP, summary));
		} catch (Exception e) {
			logger.error("Failed creating func diff view.", e);
			return errorMV(e.getMessage());
		}
	}
}
