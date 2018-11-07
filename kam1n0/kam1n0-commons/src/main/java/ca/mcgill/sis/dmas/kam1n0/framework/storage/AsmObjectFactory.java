package ca.mcgill.sis.dmas.kam1n0.framework.storage;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;

import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.cassandra.ObjectFactoryCassandra;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.ram.ObjectFactoryRAM;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

/**
 * User isolation ready. Multi-tenency support.
 */
public class AsmObjectFactory {
	private static Logger logger = LoggerFactory.getLogger(AsmObjectFactory.class);
	private String platformName;
	private String appName;

	public ObjectFactoryMultiTenancy<Binary> obj_binaries;
	public ObjectFactoryMultiTenancy<Function> obj_functions;
	public ObjectFactoryMultiTenancy<Block> obj_blocks;
	public ObjectFactoryMultiTenancy<Comment> obj_comments;

	public static AsmObjectFactory init(SparkInstance spark, String platformName, String appName) {
		try {
			AsmObjectFactory factory = new AsmObjectFactory();
			factory.platformName = platformName;
			factory.appName = appName;
			factory.obj_binaries = new ObjectFactoryRAM<>(spark);
			factory.obj_functions = new ObjectFactoryRAM<>(spark);
			factory.obj_blocks = new ObjectFactoryRAM<>(spark);
			factory.obj_comments = new ObjectFactoryRAM<>(spark);
			factory.initAll();
			return factory;
		} catch (Exception e) {
			logger.error("Failed to initilize global shared object factory...", e);
			return null;
		}

	}

	public static AsmObjectFactory init(SparkInstance spark, CassandraInstance cassandra, String platformName,
			String appName) {
		try {
			AsmObjectFactory factory = new AsmObjectFactory();
			factory.platformName = platformName;
			factory.appName = appName;
			factory.obj_binaries = new ObjectFactoryCassandra<>(cassandra, spark);
			factory.obj_functions = new ObjectFactoryCassandra<>(cassandra, spark);
			factory.obj_blocks = new ObjectFactoryCassandra<>(cassandra, spark);
			factory.obj_comments = new ObjectFactoryCassandra<>(cassandra, spark);
			factory.initAll();
			return factory;
		} catch (Exception e) {
			logger.error("Failed to initilize global shared object factory...", e);
			return null;
		}
	}

	private void initAll() throws Exception {
		obj_binaries.init(this.platformName, this.appName, Binary.class);
		obj_functions.init(this.platformName, this.appName, Function.class);
		obj_blocks.init(this.platformName, this.appName, Block.class);
		obj_comments.init(this.platformName, this.appName, Comment.class);
	}
	
	public void addBinary(long rid, Binary binary) {
		this.addBinary(rid, binary, null);
	} 

	public void addBinary(long rid, Binary binary, StageInfo stage) {

		Binary old_binary = obj_binaries.querySingle(rid, binary.binaryId);
		if (old_binary != null) {
			binary.functionIds.addAll(old_binary.functionIds);
			binary.numFunctions = binary.functionIds.size();
			obj_binaries.update(rid, binary);
		}else
			obj_binaries.put(rid, binary);
		
		Counter counter = new Counter();
		binary.functions.parallelStream().filter(func -> func != null)
				.filter(func -> old_binary == null || !old_binary.functionIds.contains(func.functionId))
				.forEach(func -> {
					obj_functions.put(rid, func, false);
					func.blocks.parallelStream().forEach(blk -> {
						obj_blocks.put(rid, blk, false);
					});
					func.comments.parallelStream().forEach(cmm -> {
						obj_comments.put(rid, cmm, false);
					});
					if(stage!=null) {
						counter.inc();
						stage.progress = counter.percentage(binary.functions.size());
					}
				});
	}

	public void dropBinary(long rid, long binaryId) {
		obj_binaries.del(rid, binaryId);
	}

	public Iterable<Function> browseFunc() {
		return obj_functions.browse();
	}

	public Iterable<BinaryMultiParts> browseBinary(long rid) {
		int batchSize = 1000;
		return Iterables.filter(Iterables.concat(//
				Iterables.transform(obj_binaries.browse(rid), bin -> {
					List<List<Long>> parts = DmasCollectionOperations.chopped(new ArrayList<>(bin.functionIds),
							batchSize);
					return Iterables.transform(parts, part -> {
						Binary binary;
						try {
							binary = bin.clone();
							binary.functionIds = new HashSet<>(part);
							binary.fill(rid, this);
							return binary.converToMultiPart();
						} catch (CloneNotSupportedException e) {
							logger.error("Failed to copy binary.", e);
						}
						return null;
					});
				})), multipart -> multipart != null);
	}

	public void clear(long rid) {
		obj_binaries.del(rid);
		obj_functions.del(rid);
		obj_blocks.del(rid);
		obj_comments.del(rid);
	}

}
