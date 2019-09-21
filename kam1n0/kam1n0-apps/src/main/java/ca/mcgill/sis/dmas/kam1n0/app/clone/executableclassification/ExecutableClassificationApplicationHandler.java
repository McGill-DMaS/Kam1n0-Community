package ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification;


import java.io.File;
import java.net.URLDecoder;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import org.apache.commons.lang3.math.NumberUtils;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
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
import ca.mcgill.sis.dmas.kam1n0.AppController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform;
import ca.mcgill.sis.dmas.kam1n0.UserController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.Access;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AccessMode;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationHandler;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfoSummary;
import ca.mcgill.sis.dmas.kam1n0.app.adata.BinaryDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.adata.ClusterDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.AbastractCloneSearchHandler;
import ca.mcgill.sis.dmas.kam1n0.app.clone.BinaryAnalysisProcedureCompositionAnalysisforExecutableClassification;
import ca.mcgill.sis.dmas.kam1n0.app.clone.BinaryIndexProcedureLSHMRforExecutableClassification;
import ca.mcgill.sis.dmas.kam1n0.app.clone.CloneSearchResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDetectionResultForWeb;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnitForClassification;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnitForClassification.SummaryWrapper;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileServingUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.MVCUtils;
import ca.mcgill.sis.dmas.kam1n0.app.util.ModelAndFragment;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;

@Controller
@RequestMapping(ExecutableClassificationApplicationMeta.appType)
@AppType(ExecutableClassificationApplicationMeta.appType)
public class ExecutableClassificationApplicationHandler extends AbastractCloneSearchHandler {

	public final static String VIEW_CLONE_FUNC = "apps/clone/ExecutableClassification/app_func_clone_render";
	public final static String VIEW_BIN_INDEX = "apps/clone/ExecutableClassification/app_request_bin_index";
	public final static String FRAG_APP_CLUSTER_LIST = "apps/clone/ExecutableClassification/app_cluster_list";
	public final static String FRAG_APP_CLASSIFIED_BIN_LIST = "apps/clone/ExecutableClassification/app_classified_binary_list";
	public final static String VIEW_BIN_CLASS = "apps/clone/ExecutableClassification/app_bin_composition";
	public final static String FRAG_APP_CONF = "platform/fragments/app_malware_conf";
	public final static String PIE_CHART = "apps/clone/ExecutableClassification/pie_chart";
	public final static String DEL_CLUSTER = "apps/clone/ExecutableClassification/del_cluster";
	public final static String VIEW_SOFTWARE_ANALYSIS_REQUEST = "apps/clone/ExecutableClassification/app_request_software_analysis";
	private static Logger logger = LoggerFactory.getLogger(ApplicationHandler.class);
	
	@Autowired
	public ExecutableClassificationApplicationHandler(ExecutableClassificationApplicationMeta meta) {
		super(meta);
	}

	@Override
	public List<String> getExamples() {
		return Arrays.asList("adler32.txt");
	}

	@Override
	public String getFuncCloneRenderFragment() {
		return VIEW_CLONE_FUNC;
	}

	@Override
	public String getBinIndexFragment() {
		return VIEW_BIN_INDEX;
	}

	public final ModelAndFragment getClusterListFragment(ApplicationInfo info) {
		return new ModelAndFragment(FRAG_APP_CLUSTER_LIST, info);
	}

	
	@GetMapping("/{appId:.+}/editApp")
	public ModelAndView showApplicationFormEdit(@PathVariable("appId") long appId, Model model) {
		try {
			ApplicationInfo info = getApplicationInfo(appId);
			model.addAttribute("confObj", info);
			model.addAttribute("applicationTypes", AppPlatform.appTypes.keySet());
			model.addAttribute("appConfForm", null);
			model.addAttribute("appConfForm", info.configuration.createView());
			model.addAttribute("edit", true);
			return MVCUtils.wrapAuthenticatedHomePage("Edit the Application.", "Please edit the required information.",
					new ModelAndFragment(FRAG_APP_CONF, model));
		} catch (Exception e) {
			logger.error("Failed to create application form..", e);
			return MVCUtils.errorMV("Failed to create application form.");
		}
	}

	@GetMapping("/{appId:.+}/pieChart")
	public ModelAndView pieChart(@PathVariable("appId") long appId, @RequestParam("id") String clusterName, Model model) {
		try {
			ApplicationInfo info = getApplicationInfo(appId);
			Cluster clu = ((ExecutableClassificationApplicationMeta)(this.meta)).clusterFactory.querySingle(appId,clusterName);
			clu.classDist.keySet().stream().forEach(k->{clu.classDist.compute(k, (ke,v)->v*100.);});
			model.addAttribute("dist", clu.classDist);
			model.addAttribute("clusterName", clusterName);
			model.addAttribute("info", info);
			return MVCUtils.wrapAuthenticatedHomePage("", "",
					new ModelAndFragment(PIE_CHART, model));
		} catch (Exception e) {
			logger.error("Failed to create application form..", e);
			return MVCUtils.errorMV("Failed to create application form.");
		}
	}

	@GetMapping("/{appId:.+}/delCluster")
	public ModelAndView delCluster(@PathVariable("appId") long appId, @RequestParam("id") String clusterName, Model model) {
		try {
			ExecutableClassificationApplicationMeta appMeta = (ExecutableClassificationApplicationMeta)(this.meta);
			Cluster clu = appMeta.clusterFactory.querySingle(appId,clusterName);


			ArrayList<String> classes = new ArrayList<String>();;
			clu.classDist.keySet().stream().forEach(cls->classes.add(cls));

			SoftwareClassMeta classMeta = appMeta.classFactory.querySingle(appId, clu.className);
			classMeta.classClusterList.remove(clusterName);
			appMeta.classFactory.put(appId, classMeta);

			appMeta.clusterFactory.del(appId,clusterName);


			List<Cluster> clusters = ((ExecutableClassificationApplicationMeta)(this.meta)).clusterFactory.queryMultipleBaisc(appId).collect();


			Map<Long, Double> binaryNClusters = new HashMap<Long, Double>();
			Map<Long, Long> functionIDtobinID = new HashMap<Long, Long>();
			Map<Long, String> binaryIDtoClass = new HashMap<Long, String>();

			List<SoftwareClassMeta> softwareClassMetas = appMeta.classFactory.queryMultipleBaisc(appId).collect();
			for (SoftwareClassMeta met : softwareClassMetas) {

				for (long binID : met.classBinaryList) {
					binaryIDtoClass.put(binID, met.className);
					binaryNClusters.put(binID, 0.);
					List<Function> funcList = appMeta.getFunctions(appId, binID);
					for (Function func : funcList) {
						functionIDtobinID.put(func.functionId, binID);
				    }
			    }
			}


			clusters.stream().forEach(cluster -> {
				Map<Long, Boolean> counted = new HashMap<Long, Boolean>();
				cluster.functionIDList.stream().forEach(id -> {
					long BID = functionIDtobinID.get(id);
					if (!counted.containsKey(BID)) {
						counted.put(BID, true);
						String cls = binaryIDtoClass.get(BID);
						double d = cluster.classDist.get(cls);
						binaryNClusters.compute(BID, (k, v) -> v + d);
					}
				});
			});


			classes.stream().forEach(cls -> {
				double avg;
				SoftwareClassMeta clsMeta = appMeta.classFactory.querySingle(appId, cls);
				if (clsMeta == null)
					return;
				//String avgs = "avg";
				//average
				//avg = clsMeta.classBinaryList.stream().map(BID -> binaryNClusters.get(BID)).reduce(0., Double::sum)
				//		/ clsMeta.classBinaryList.size();

				//median
				//avgs = "median";
				List<Double> ncls = clsMeta.classBinaryList.stream().map(BID -> binaryNClusters.get(BID)).collect(Collectors.toList());
				Collections.sort(ncls);
				avg = ncls.get(ncls.size()/2);


				clsMeta.averageNCluster = avg;
				appMeta.classFactory.put(appId, clsMeta);
			});

			model.addAttribute("clusterName", clusterName);
			return MVCUtils.redirectMV(getHomePath(ExecutableClassificationApplicationMeta.appType,appId));
			//return MVCUtils.wrapAuthenticatedHomePage(clusterName+" Deleted", clusterName+" Deleted 2",
			//		new ModelAndFragment(DEL_CLUSTER, model));
		} catch (Exception e) {
			logger.error("Failed to create application form..", e);
			return MVCUtils.errorMV("Failed to create application form.");
		}
	}


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
			controller.updateFullApplicationInstance(info);
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


	@RequestMapping(value = "/{appId:.+}/push_files", method = RequestMethod.POST)
	public final @ResponseBody Map<String, Object> postFiles(@PathVariable("appId") long appId,
			@RequestParam(value = "files", defaultValue = "") Object[] objs, @RequestParam("softwareClass") String softwareClass,
			@RequestParam("trainOrNot") final boolean trainOrNot, @RequestParam("clusterOrNot") final boolean clusterOrNot) {

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
				ApplicationInfo appInfo = meta.getInfo(appId);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_FILES, nobjs);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_CLASS, softwareClass);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_TRAIN, trainOrNot);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_CLUSTER, clusterOrNot);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_SIMILARITY_THRESHOLD, ((ExecutableClassificationApplicationConfiguration)(appInfo.configuration)).similarity_threshold_for_cluster);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_DISTRIBUTION_THRESHOLD, ((ExecutableClassificationApplicationConfiguration)(appInfo.configuration)).cluster_class_distribution_significance);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_N_EXECUTABLE_THRESHOLD, ((ExecutableClassificationApplicationConfiguration)(appInfo.configuration)).min_exe_per_cluster);
				params.put(BinaryIndexProcedureLSHMRforExecutableClassification.KEY_CLUSTER_METHOD, ((ExecutableClassificationApplicationConfiguration)(appInfo.configuration)).clusterModel);
				String idstr = this.meta.submitJob(appId, meta.getAppType(), appInfo.name, name,
				BinaryIndexProcedureLSHMRforExecutableClassification.class, params);
				return ImmutableMap.of("jid", idstr);
			} catch (Exception e) {
				return ImmutableMap.of("error", e.getMessage());
			}
		}
	}

	@RequestMapping(value = "/{appId:.+}/class_list", method = RequestMethod.GET)
	@ResponseBody
	public final List<SoftwareClassMeta> getClassedFileLists(@PathVariable("appId") long appId) {
		List<SoftwareClassMeta> class_list_RDD = ((ExecutableClassificationApplicationMeta)(this.meta)).classFactory.queryMultipleBaisc(appId).collect();
		int total_n = 0;
		for(SoftwareClassMeta cls:class_list_RDD )
		{
			List<Cluster> clusters = ((ExecutableClassificationApplicationMeta)(this.meta)).clusterFactory.queryMultiple(appId, "clusterName",cls.classClusterList).collect();
			for(Cluster clu:clusters)
			{
				total_n += clu.functionIDList.size();
			}
		}
		logger.info("total n functions in clusters:"+Integer.toString(total_n));
		return class_list_RDD;
	}

	@RequestMapping(value = "/{appId:.+}/classified_file_list", method = RequestMethod.GET)
	@ResponseBody
	public final List<BinaryDataUnit> getClassedFileLists(@PathVariable("appId") long appId,@RequestParam("id") String className) {
		SoftwareClassMeta classMeta = ((ExecutableClassificationApplicationMeta)(this.meta)).classFactory.querySingle(appId, className);
		List<BinaryDataUnit> result = meta.platform.objectFactory.obj_binaries.queryMultipleBaisc(appId, "binaryId",classMeta.classBinaryList).collect().stream().map(BinaryDataUnit::new).collect(Collectors.toList());
		logger.info("total number of functions:"+Long.toString(result.stream().map(e->Long.parseLong(e.numFunctions)).reduce(0L, Long::sum)));
		return result;
	}

	@RequestMapping(value = "/{appId:.+}/cluster_info", method = RequestMethod.GET)
	@ResponseBody
	public final List<ClusterDataUnit> getClusterInfos(@PathVariable("appId") long appId) {
		List<Cluster> clusters = ((ExecutableClassificationApplicationMeta)(this.meta)).clusterFactory.queryMultipleBaisc(appId).collect();
		List<ClusterDataUnit> result = clusters.stream().map(ClusterDataUnit::new).collect(Collectors.toList());
		return result;
	}

	@RequestMapping(value = "/{appId:.+}/class_cluster_info", method = RequestMethod.GET)
	@ResponseBody
	public final List<ClusterDataUnit> getClassClusterInfos(@PathVariable("appId") long appId, @RequestParam("id") String className) {
		SoftwareClassMeta classMeta = ((ExecutableClassificationApplicationMeta)(this.meta)).classFactory.querySingle(appId, className);
		List<Cluster> clusters = ((ExecutableClassificationApplicationMeta)(this.meta)).clusterFactory.queryMultiple(appId, "clusterName",classMeta.classClusterList).collect();
		List<ClusterDataUnit> result = clusters.stream().map(ClusterDataUnit::new).collect(Collectors.toList());
		return result;
	}

	@RequestMapping(value = "/{appId:.+}/cluster_func_info", method = RequestMethod.GET)
	@ResponseBody
	public final List<FunctionDataUnit> getClusterFunctionInfos(@PathVariable("appId") long appId,
			@RequestParam("id") String clusterName) {
		Cluster clu = ((ExecutableClassificationApplicationMeta)(this.meta)).clusterFactory.querySingle(appId,clusterName);
		List<FunctionDataUnit> result = this.meta.platform.objectFactory.obj_functions.queryMultipleBaisc(appId, "functionId", clu.functionIDList).collect().stream().map(func -> new FunctionDataUnit(func, true)).collect(Collectors.toList());
		return result;
	}


	public final ModelAndFragment getClassifiedBinaryListFragment(ApplicationInfo info) {
		return new ModelAndFragment(FRAG_APP_CLASSIFIED_BIN_LIST, info);
	}

	@RequestMapping(value = "/{appId:.+}/BinaryComposition", method = RequestMethod.GET)
	@Access(AccessMode.READ)
	public ModelAndView searchBinaryRenderer(@PathVariable("appId") long appId) {
		return MVCUtils.wrapAuthenticatedRenderer(new ModelAndFragment(VIEW_BIN_CLASS, meta.getInfo(appId)));
	}

	@RequestMapping(value = "/{appId:.+}/BinaryComposition", method = RequestMethod.POST)
	@Access(AccessMode.READ)
	public @ResponseBody Map<String, Object> searchBinaryRenderer(@PathVariable("appId") long appId,
			@RequestParam("fileName") String fileName,
			@RequestParam(value = "keyword", defaultValue = "*") String keyword, HttpServletRequest request) {

		try {
			String cloneDetail = request.getParameter("cloneDetail");
			String clusterCloneDetail = request.getParameter("clusterCloneDetail");
			String list = request.getParameter("list");
			String cluster_list = request.getParameter("cluster_list");
			String addRange = request.getParameter("addRange");
			String summary = request.getParameter("summary");
			String comb = request.getParameter("comb");
			String[] not_selected = request.getParameterValues("not_selected[]");

			fileName = URLDecoder.decode(fileName, "UTF-8");
			BinarySearchUnitForClassification servingObj = FileServingUtils.getFileRelatedObject(fileName, BinarySearchUnitForClassification.class);

			if (clusterCloneDetail != null) {
				FunctionCloneDetectionResultForWeb result = servingObj.getClusterCloneDetail(clusterCloneDetail);
				FunctionCloneDataUnit unit = new FunctionCloneDataUnit(Lists.newArrayList(result));
				unit.generateCloneGraph();
				return ImmutableMap.of("object", unit);
			}

			if(comb != null){
				SummaryWrapper wrapper = servingObj.summarize();
				long addrStart = 0;
				long addrEnd = NumberUtils.toLong(request.getParameter("addrEnd"), Long.MAX_VALUE);
				return ImmutableMap.of("object", wrapper,"object2",servingObj.getClusterCloneInfoList(addrStart, addrEnd, not_selected, keyword));
			}

			if (list != null) {
				long addrStart = NumberUtils.toLong(request.getParameter("addrStart"), 0);
				long addrEnd = NumberUtils.toLong(request.getParameter("addrEnd"), Long.MAX_VALUE);
				return ImmutableMap.of("object",
						servingObj.getCloneInfoList(addrStart, addrEnd, not_selected, keyword));
			}

			if (cluster_list != null) {
				long addrStart = NumberUtils.toLong(request.getParameter("addrStart"), 0);
				long addrEnd = NumberUtils.toLong(request.getParameter("addrEnd"), Long.MAX_VALUE);
				return ImmutableMap.of("object",
						servingObj.getClusterCloneInfoList(addrStart, addrEnd, not_selected, keyword));
			}

			if (addRange != null) {
				return ImmutableMap.of("object", servingObj.getAddressRanges());
			}

			if (summary != null) {
				SummaryWrapper wrapper = servingObj.summarize();
				return ImmutableMap.of("object", wrapper);
			}
		} catch (Exception e) {
			logger.error("Failed to process query.", e);
		}
		return ImmutableMap.of("error", "Unacceptable request.");

	}


	@RequestMapping(value = "/{appId:.+}/search_bins", method = RequestMethod.POST)
	@Access(AccessMode.READ)
	public @ResponseBody Map<String, Object> searchBinary(@PathVariable("appId") long appId,
			@RequestParam(value = "threshold", defaultValue = "0.5") double threshold,
			@RequestParam(value = "avoidSameBinary", defaultValue = "FALSE") final boolean avoidSameBinary,
			@RequestParam(value = "topk", defaultValue = "10") int topk, //
			@RequestParam(value = "bins") Object[] objs) {

		ArrayList<Object> nobjs = new ArrayList<>();
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		String name = auth.getName();
		String tmpDir = Environment.getUserTmpDir(name);
		for (Object obj: objs) {
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
			//obj = new_file;
			nobjs.add(new_file);
		} else if (obj instanceof String) {
			BinarySurrogate surrogate;
			try {
				surrogate = BinarySurrogate.loadFromJson((String) obj);
				surrogate.processRawBinarySurrogate();
				nobjs.add(surrogate);
			} catch (Exception e) {
				logger.error("Failed to process submited mutipart file", e);
				return ImmutableMap.of("error", "Upload failes. Please check server log. " + obj.getClass().getName());
			}
		} else {
			logger.error("Unsupported type {}", obj.getClass().getName());
			return ImmutableMap.of("error", "Upload failes. Please check server log." + obj.getClass().getName());
		}
		}
		Map<String, Object> params = new HashMap<String, Object>();
		params.put(BinaryAnalysisProcedureCompositionAnalysisforExecutableClassification.KEY_FILES, nobjs);
		params.put(BinaryAnalysisProcedureCompositionAnalysisforExecutableClassification.KEY_THRESHOLD, threshold);
		params.put(BinaryAnalysisProcedureCompositionAnalysisforExecutableClassification.KEY_FILTER, avoidSameBinary);
		params.put(BinaryAnalysisProcedureCompositionAnalysisforExecutableClassification.KEY_TOP, topk);
		try {
			ApplicationInfo appInfo = meta.getInfo(appId);
			String id = this.meta.submitJob(appId, meta.getAppType(), appInfo.name, name,
					BinaryAnalysisProcedureCompositionAnalysisforExecutableClassification.class, params);
			return ImmutableMap.of("jid", id);
		} catch (Exception e) {
			logger.error("Failed submitting job.", e);
			return ImmutableMap.of("error", e.getMessage());
		}

	}
	
	
	
	
	
	@Override
	public ModelAndView getHomeModelAndViewImpl(long appId) {
		ApplicationInfoSummary summary = meta.getInfoSummary(appId);
		ModelAndFragment title = getAppTileFragment(summary);
		ModelAndFragment binaryList = getClassifiedBinaryListFragment(summary.basicInfo);
		ModelAndFragment clusterList = getClusterListFragment(summary.basicInfo);
		
		ModelAndFragment request = new ModelAndFragment(VIEW_SOFTWARE_ANALYSIS_REQUEST, //
				ImmutableMap.of(//
						"summary", summary, //
						"queryModel", ImmutableMap.of(//
								"summary", summary, //
								"examples", getExamples()), //
						"indexFragment", getBinIndexFragment(), //
						"indexModel", ImmutableMap.of(//
								"summary", summary //
						))//
		);
		return MVCUtils.wrapAuthenticatedHomePage(summary.basicInfo.applicationType + '/',
				Long.toString(summary.basicInfo.appId), title, clusterList, binaryList, request);
	}

	
	
	@RequestMapping(value = "/{appId:.+}/reindex", method = RequestMethod.POST)
	public final @ResponseBody Map<String, Object> reIndex() {
		return null;
	}

}
