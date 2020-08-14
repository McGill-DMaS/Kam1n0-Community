package ca.mcgill.sis.dmas.kam1n0;

import javax.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalJobScheduler;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

@Component
public class GlobalResources {

	private static Logger logger = LoggerFactory.getLogger(GlobalResources.class);

	public SparkInstance spark;
	public CassandraInstance cassandra;
	public DisassemblyFactory disassemblyFactory;
	public LocalJobScheduler scheduler;
	public final String platform_name = "kam1n0";
	public final String global_name = "global";
	public final Long global_key = -1l;
	public final String version = "2.0.0";

	public GlobalResources() {

		try {
			cassandra = CassandraInstance.createEmbeddedInstance("test", false, false);
			cassandra.init();
			spark = SparkInstance.createLocalInstance(cassandra.getSparkConfiguration());
			spark.init();
			cassandra.setSparkInstance(spark);

			disassemblyFactory = DisassemblyFactory.getDefaultDisassemblyFactory();
			scheduler = new LocalJobScheduler(60 * 3, 100);

		} catch (Exception e) {
			logger.error("Failed to create a new platform..", e);
		}
	}

	@PreDestroy
	public void cleanUp() throws Exception {
		logger.info("Shutting down disassembly factory..");
		disassemblyFactory.close();
		logger.info("Shutting down embeded cassandra instance.");
		cassandra.close();
		logger.info("Shutting down embeded spark instance.");
		spark.close();
		logger.info("Shutting down scheduler.");
		scheduler.close();
		logger.info("Shut down routine completed.");
	}

	public static void main(String[] args) throws Exception {
		GlobalResources res = new GlobalResources();
		res.cleanUp();
	}

}
