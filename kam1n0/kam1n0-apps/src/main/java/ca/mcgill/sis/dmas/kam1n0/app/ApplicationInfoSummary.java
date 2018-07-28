package ca.mcgill.sis.dmas.kam1n0.app;

import java.util.HashMap;

public class ApplicationInfoSummary {
	public ApplicationInfoSummary(ApplicationInfo info, ApplicationSummary summary2) {
		this.basicInfo = info;
		this.summary = summary2;
		this.link = ApplicationHandler.getHomePath(info.applicationType, info.appId);
		this.prefix = ApplicationHandler.getPrefixPath(info.applicationType, info.appId);
	}

	public ApplicationInfo basicInfo;
	public ApplicationSummary summary;
	public String link;
	public String prefix;

	public HashMap<String, Object> appAttrs = new HashMap<>();

	public Object getAppAttr(String key, Object deflt) {
		return appAttrs.getOrDefault(key, deflt);
	}

	public static class ApplicationSummary {
		public long numBinaries;
		public long numFunctions;
		public long numBasicBlocks;
	}

	public static class QuerySummary {

	}
}
