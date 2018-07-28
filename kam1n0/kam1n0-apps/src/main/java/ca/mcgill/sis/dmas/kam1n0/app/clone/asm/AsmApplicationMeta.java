package ca.mcgill.sis.dmas.kam1n0.app.clone.asm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.AppController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.clone.CloneSearchResources;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.DetectorsKam;

@Component
@AppType(AsmApplicationMeta.appType)
public class AsmApplicationMeta extends ApplicationMeta {

	public final static String appType = "/asm-clone";

	@Override
	public String getAppType() {
		return appType;
	}

	private static Logger logger = LoggerFactory.getLogger(AsmApplicationMeta.class);

	Cache<AsmApplicationConfiguration, CloneSearchResources> map = CacheBuilder.newBuilder().maximumSize(5).build();

	@Autowired
	public AsmApplicationMeta(AppPlatform platform, AppController controller) {
		super(platform, controller);
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T extends ApplicationResources> T getResource(long appId) {
		ApplicationInfo info = getInfo(appId);
		AsmApplicationConfiguration conf = (AsmApplicationConfiguration) info.configuration;
		CloneSearchResources val = map.getIfPresent(info.configuration);
		if (val == null) {
			try {
				logger.info("Loading new resources. It may take a while to process the first query.");
				AsmProcessor processor = new AsmProcessor(conf.architectureType.retrieveDefinition(),
						conf.normalizationSetting);
				FunctionCloneDetector detector = DetectorsKam.getLshAdaptiveSubGraphFunctionCloneDetectorCassandra(
						platform.spark, platform.cassandra, platform.objectFactory, processor, conf.kStart, conf.kMax,
						conf.l, conf.mSplit, 0);
				detector.init();
				val = new CloneSearchResources(platform.objectFactory, detector, processor.parser);
				map.put(conf, val);
			} catch (Exception e) {
				logger.error("Failed to get resources.", e);
			}
		}
		return (T) val;
	}

	@Override
	public void cleanUpResource(long appId) {
		ApplicationInfo info = getInfo(appId);
		AsmApplicationConfiguration conf = (AsmApplicationConfiguration) info.configuration;
		CloneSearchResources res = getResource(appId);
		res.detector.clear(appId);
		map.invalidate(conf);
	}

}
