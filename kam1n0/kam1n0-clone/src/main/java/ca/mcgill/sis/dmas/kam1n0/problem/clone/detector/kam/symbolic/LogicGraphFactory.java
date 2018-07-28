package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic;

import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.AsBytes;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedPrimary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.ObjectFactoryMultiTenancy.KeyedSecondary;
import ca.mcgill.sis.dmas.kam1n0.graph.BlockLogicWrapper;
import ca.mcgill.sis.dmas.kam1n0.graph.LogicGraph;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra.ObjectFactoryCassandra;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.ram.ObjectFactoryRAM;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class LogicGraphFactory {

	private static Logger logger = LoggerFactory.getLogger(LogicGraphFactory.class);

	public static class LogicGraphWrapper implements Serializable {

		private static final long serialVersionUID = -3667075501959881678L;

		@KeyedSecondary
		public long blockId;

		@AsBytes
		public LogicGraph graph;

		public LogicGraphWrapper(long blockId, LogicGraph graph) {
			this.blockId = blockId;
			this.graph = graph;
		}

		public LogicGraphWrapper() {
		}

	}

	public static class VexWrapper implements Serializable {

		private static final long serialVersionUID = -3667075501959881678L;

		@KeyedSecondary
		public long blockId;

		@AsBytes
		public List<List<String>> vex;

		public VexWrapper(long blockId, List<List<String>> vex) {
			this.blockId = blockId;
			this.vex = vex;
		}

		public VexWrapper() {
		}

	}

	public ObjectFactoryMultiTenancy<LogicGraphWrapper> obj_logics;
	public ObjectFactoryMultiTenancy<VexWrapper> obj_vex;

	public void delete(long rid) {
		obj_logics.del(rid);
		obj_vex.del(rid);
	}

	public LogicGraph getLogicGraph(long rid, long blockId) {
		LogicGraphWrapper wrapper = obj_logics.querySingle(rid, blockId);
		if (wrapper == null)
			return null;
		return wrapper.graph;
	}

	public List<List<String>> getVex(long rid, long blockId) {
		VexWrapper wrapper = obj_vex.querySingle(rid, blockId);
		if (wrapper == null)
			return null;
		return wrapper.vex;
	}

	public void setLogicGraph(long rid, BlockLogicWrapper graph) {
		LogicGraphWrapper wrapper = new LogicGraphWrapper(graph.getBlock().blockId, graph.getLogic());
		obj_logics.put(rid, wrapper);
		obj_vex.put(rid, new VexWrapper(graph.getBlock().blockId, graph.getVex()));
	}

	public static BlockLogicWrapper translate(Block blk) {
		if (blk instanceof BlockLogicWrapper) // may be processed in the diassembly step
			return (BlockLogicWrapper) blk;
		return new BlockLogicWrapper(blk);
	}

	public static List<BlockLogicWrapper> translate(List<Block> blks) {
		return blks.stream().map(LogicGraphFactory::translate).collect(Collectors.toList());
	}

	public static LogicGraphFactory init(SparkInstance spark, String platformName, String appName) {
		try {
			LogicGraphFactory factory = new LogicGraphFactory();
			factory.obj_logics = new ObjectFactoryRAM<LogicGraphWrapper>(spark);
			factory.obj_logics.init(platformName, appName, LogicGraphWrapper.class);
			factory.obj_vex = new ObjectFactoryRAM<VexWrapper>(spark);
			factory.obj_vex.init(platformName, appName, VexWrapper.class);
			return factory;
		} catch (Exception e) {
			logger.error("Failed to create logic graph factory..", e);
			return null;
		}
	}

	public static LogicGraphFactory init(SparkInstance spark, CassandraInstance cassandra, String platformName,
			String appName) {
		try {
			LogicGraphFactory factory = new LogicGraphFactory();
			factory.obj_logics = new ObjectFactoryCassandra<LogicGraphWrapper>(cassandra, spark);
			factory.obj_logics.init(platformName, appName, LogicGraphWrapper.class);
			factory.obj_vex = new ObjectFactoryCassandra<VexWrapper>(cassandra, spark);
			factory.obj_vex.init(platformName, appName, VexWrapper.class);
			return factory;
		} catch (Exception e) {
			logger.error("Failed to create logic graph factory..", e);
			return null;
		}
	}
}
