package ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification;

import java.io.File;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;
import ca.mcgill.sis.dmas.kam1n0.AppController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform;
import ca.mcgill.sis.dmas.kam1n0.GlobalResources;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.clone.CloneSearchResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.asm.AsmApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmRawFunctionParser;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Comment;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra.ObjectFactoryCassandra;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.rep.GeneralVectorIndex;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rep.ExecutableClassificationAsm2VecDetectorIntegration;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema.HashSchemaTypes;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;

@Component
@AppType(ExecutableClassificationApplicationMeta.appType)
public class ExecutableClassificationApplicationMeta extends ApplicationMeta {
	
	@Component
	public static class Wrapper {
		private static ExecutableClassificationApplicationMeta meta;

		@Autowired
		public Wrapper(ExecutableClassificationApplicationMeta meta_ins) {
			meta = meta_ins;
		}

		public static ExecutableClassificationApplicationMeta getMeta() {
			return meta;
		}

	}

	public final static String appType = "/ExecutableClassification";
	public final static String modelName = "/ExecutableClassification.bin";
	public ObjectFactoryMultiTenancy<SoftwareClassMeta> classFactory;
	public ObjectFactoryMultiTenancy<Cluster> clusterFactory;

	@Override
	public String getAppType() {
		return appType;
	}

	private static Logger logger = LoggerFactory.getLogger(ExecutableClassificationApplicationMeta.class);

	Cache<Long, CloneSearchResources> map = CacheBuilder.newBuilder().maximumSize(5).build();

	private transient CassandraInstance cassandra;

	private transient SparkInstance spark;

	@Autowired
	public ExecutableClassificationApplicationMeta(AppPlatform platform, AppController controller, GlobalResources res) {
		super(platform, controller);

		try {
			this.cassandra = res.cassandra;
			this.spark = res.spark;
			classFactory = new ObjectFactoryCassandra<SoftwareClassMeta>(res.cassandra, res.spark);
			classFactory.init(res.platform_name, res.global_name, SoftwareClassMeta.class);
			


			clusterFactory = new ObjectFactoryCassandra<Cluster>(res.cassandra, res.spark);
			clusterFactory.init(res.platform_name, res.global_name, Cluster.class);
			MathUtilities.createExpTable();
		} catch (Exception e) {
			logger.error("Failed to create application meta for asm2vec", e);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T extends ApplicationResources> T getResource(long appId) {
		
		/*
		 * to identify what objectFactory is used for
		 * 
		 */
		
		ApplicationInfo info = getInfo(appId);
		ExecutableClassificationApplicationConfiguration conf = (ExecutableClassificationApplicationConfiguration) info.configuration;
		Asm2VecNewParam param = conf.convertToParam();
		CloneSearchResources val = map.getIfPresent(appId);
		if (val == null) {
			try {
				logger.info("Loading new resources. It may take a while to process the first query.");
				AsmLineNormalizationResource res = new AsmLineNormalizationResource(
						conf.architectureType.retrieveDefinition());
				// used to parse plain text code into binary
				AsmRawFunctionParser parser = new AsmRawFunctionParser(res);
				String file = getModelName(appId);
				ExecutableClassificationAsm2VecDetectorIntegration model = null;
				if (new File(file).exists()) {
					try {
						model = DmasByteOperation.loadObject(file);
					} catch (Exception e) {
						logger.error("Failed to load trained model for {}. Creating a new one.", appId);
						model = new ExecutableClassificationAsm2VecDetectorIntegration(platform.objectFactory, param);
					}
				} else {
					model = new ExecutableClassificationAsm2VecDetectorIntegration(platform.objectFactory, param);
				}

				// index with different param but essentially on the same table; seperated by
				// appId.
				GeneralVectorIndex index = new GeneralVectorIndex(this.spark, this.cassandra, param.vec_dim,
						conf.kStart, conf.kMax, conf.l, conf.mSplit, HashSchemaTypes.SimHash, false);
				model.init();
				model.customized_init(this::saveMode, index, platform.objectFactory);
				val = new CloneSearchResources(platform.objectFactory, model, parser);
				val.meta = this;

				map.put(appId, val);
			} catch (Exception e) {
				logger.error("Failed to get resources.", e);
			}
		}
		return (T) val;
	}

	public String getModelName(long appId) {
		return Environment.getAppFolder(appId) + modelName;
	}

	public void saveMode(long appId, ExecutableClassificationAsm2VecDetectorIntegration model) {
		try {
			DmasByteOperation.saveObject(model, getModelName(appId));
		} catch (IOException e) {
			logger.error("Failed to save model for " + appId, e);
		}
	}

	@Override
	public void cleanUpResource(long appId) {
		ApplicationInfo info = getInfo(appId);
		ExecutableClassificationApplicationConfiguration conf = (ExecutableClassificationApplicationConfiguration) info.configuration;
		CloneSearchResources res = getResource(appId);
		res.detector.clear(appId);
		map.invalidate(conf);
	}

}
