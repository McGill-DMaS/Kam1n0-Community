package ca.mcgill.sis.dmas.kam1n0.app;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.kam1n0.AppController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionCommentWrapper;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobProcedure;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Comment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class ApplicationMeta {

	private static Logger logger = LoggerFactory.getLogger(ApplicationMeta.class);

	public AppPlatform platform = null;
	private AppController controller;

	public ApplicationMeta(AppPlatform platform, AppController controller) {
		this.platform = platform;
		this.controller = controller;
	}

	public abstract String getAppType();

	public abstract <T extends ApplicationResources> T getResource(long appId);

	public abstract void cleanUpResource(long appId);

	public final ApplicationInfo getInfo(long appId) {
		return controller.getAppInfo(appId);
	}

	public boolean checkFunc(long appId, long fid) {
		return platform.objectFactory.obj_functions.check(appId, fid);
	}

	public final ApplicationInfoSummary getInfoSummary(long appId) {
		return controller.getAppInfoSummary(appId);
	}

	public final List<FunctionCommentWrapper> getComment(long appId, long fid) {
		return platform.getComments(appId, fid);
	}

	public final boolean putComment(long appId, Comment comment) {
		return platform.putComment(appId, comment);
	}

	public FunctionDataUnit getFunction(long appId, long fid) {
		return platform.getFunctionFlow(appId, fid);
	}

	public List<Binary> getBinaries(long appId) {
		JavaRDD<Binary> bins = platform.objectFactory.obj_binaries.queryMultipleBaisc(appId);
		if (bins == null)
			return new ArrayList<>();
		return bins.collect();
	}

	public Binary getBinary(long appId,long binaryId) {
		Binary bin = platform.objectFactory.obj_binaries.querySingleBaisc(appId,binaryId);
		return bin;
	}

	public void delBinary(long appId,long binaryId) {
		platform.objectFactory.obj_binaries.del(appId,binaryId);
		return;
	}

	public void delFunction(long appId,long functionId) {
		platform.objectFactory.obj_functions.del(appId,functionId);
		return;
	}


	public void delBlock(long appId,long blockId) {
		platform.objectFactory.obj_blocks.del(appId,blockId);
		return;
	}

	public List<Function> getFunctions(long appId) {
		JavaRDD<Function> funcs = platform.objectFactory.obj_functions.queryMultipleBaisc(appId);
		if (funcs == null)
			return new ArrayList<>();
		return funcs.collect();
	}

	public List<Function> getFunctions(long appId, long binaryId) {
		Binary bin = platform.objectFactory.obj_binaries.querySingle(appId, binaryId);
		if (bin == null || bin.functionIds.size() == 0)
			return new ArrayList<>();
		JavaRDD<Function> funcs = platform.objectFactory.obj_functions.queryMultipleBaisc(appId, "functionId",
				bin.functionIds);
		if (funcs == null)
			return new ArrayList<>();
		List<Function> dfuncs = funcs.collect();
		return dfuncs;
	}

	public final void delete(long appId) {
		cleanUpResource(appId);
		controller.deleteAppInfo(appId);
		platform.objectFactory.clear(appId);
	}

	public final String submitJob(long appId, String appType, String appName, String userName,
			Class<? extends LocalDmasJobProcedure> procedure, Map<String, Object> params) throws Exception {
		ApplicationInfo info = getInfo(appId);
		if (info == null)
			throw new Exception("Application not found");
		String jobIdOrErrorMsg = platform.scheduler.submitJob(appId, appType, appName, getResource(appId), userName,
				procedure, params);
		return jobIdOrErrorMsg;
	}

	public final LocalJobProgress queryJob(String userName, Class<? extends LocalDmasJobProcedure> procedure) {
		LocalJobProgress progress = platform.scheduler.getJobProgress(userName,
				LocalDmasJobProcedure.getJobName(procedure));
		return progress;
	}

}
