/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.kam1n0.app.clone.adata;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.ObjectWriter;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.ArrayListMultimap;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.Reporter;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.app.adata.BlockDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnit.RenderInfo.InfoEntry;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnit.RenderInfo.SummaryInfo;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public class BinarySearchUnit implements AutoCloseable {

	public File file;

	private static final String FUNCMAP = "FUNCMAP";
	private static final String CLONEDETAILS = "CLONEDETAILS";
	private static final String BINNAMEID = "BIN_NAMEID";
	private static final String BINIDNAME = "BIN_IDNAME";
	private static final String CLONEINFO = "CLONEINFO";
	private static final String CLONESTAT = "CLONESTAT";
	private static final String PROPERTIES = "PROP";
	private static final String PROP_SUM = "PROP_SUM";
	private static final String PROP_BOUN = "PROP_BOUN";
	private static final String PROP_RID = "PROP_RID";

	private transient static Logger logger = LoggerFactory.getLogger(BinarySearchUnit.class);

	private transient DB db;

	private ConcurrentMap<String, byte[]> functionMap; // function id ->
	// function

	private ConcurrentMap<String, byte[]> cloneDetails; // function
	// id
	// ->
	// clone
	// info

	private static ObjectMapper mapper = new ObjectMapper();

	public ConcurrentMap<String, String> binaryIdToNameMap;
	public ConcurrentMap<String, String> binaryNameToIdMap;
	public ConcurrentNavigableMap<String, Boolean> binaryStats;
	public ConcurrentMap<String, String> properties;
	private ConcurrentNavigableMap<Long, InfoEntry> cloneInfoEntry;

	public SummaryInfo summary = new SummaryInfo();
	public List<Long> boundaries = new ArrayList<>();

	public static class SummaryWrapper {
		public String fileName;
		public SummaryInfo summaryInfo;
		public Map<String, String> binaryIdToNameMap;
		public Map<String, String> binaryNameToIdMap;
	}

	public SummaryWrapper summarize() {
		SummaryWrapper wrapper = new SummaryWrapper();
		wrapper.summaryInfo = this.summary;
		wrapper.fileName = this.file.getName();
		wrapper.binaryIdToNameMap = binaryIdToNameMap;
		wrapper.binaryNameToIdMap = binaryNameToIdMap;
		return wrapper;
	}

	private long appId;

	public void addBinary(String binaryName, String id) {
		if (!binaryNameToIdMap.containsKey(binaryName)) {
			binaryNameToIdMap.put(binaryName, id);
			binaryIdToNameMap.put(id, binaryName);
		}
	}

	/**
	 * If keyword-search is activated, ignore address range (no pagination).
	 * 
	 * @param addrStart
	 * @param addrEnd
	 * @param not_selected
	 * @param keyWord
	 * @return
	 */
	public RenderInfo getCloneInfoList(long addrStart, long addrEnd, String[] not_selected, String keyWord) {
		RenderInfo rin = new RenderInfo();
		HashSet<String> filter = new HashSet<>();
		if (not_selected != null)
			Arrays.stream(not_selected).forEach(lg_val -> filter.add(lg_val));
		String tkw = keyWord.trim().toLowerCase();
		boolean keyword_search = !tkw.equals("*") && tkw.length() > 0;

		Map<Long, InfoEntry> map = null;
		if (keyword_search)
			map = cloneInfoEntry;
		else
			map = cloneInfoEntry.subMap(addrStart, true, addrEnd, false);

		rin.list = map.values().stream().filter(info -> !keyword_search || info.fn.toLowerCase().contains(tkw))
				.filter(info -> {
					if (not_selected == null)
						return true;
					info.mxs.keySet().removeAll(filter);
					return info.mxs.size() > 0;
				}).collect(Collectors.toList());

		return rin;
	}

	public FunctionCloneDetectionResultForWeb getCloneDetail(String fid) {
		try {
			return mapper.readValue(this.cloneDetails.get(fid), FunctionCloneDetectionResultForWeb.class);
		} catch (Exception e) {
			logger.error("Failed to load " + fid, e);
			return null;
		}
	}

	public FunctionDataUnit getFunction(long fid, AsmObjectFactory factory) {
		try {
			if (factory != null) {
				Function func = factory.obj_functions.querySingle(this.appId, fid);
				if (func != null)
					return new FunctionDataUnit(func);
			}
			byte[] val = this.functionMap.get(Long.toString(fid));
			if (val != null)
				return mapper.readValue(val, FunctionDataUnit.class);
			return null;
		} catch (Exception e) {
			logger.error("Failed to load " + fid, e);
			return null;
		}
	}

	/**
	 * Page ranges are now pre-caculated. Since the number of functions between each
	 * fix interval varies a lot. Return type is String since JS do not support
	 * long/double.
	 * 
	 * @param length
	 * @param keyword
	 * @return
	 */
	public List<String> getAddressRanges() {
		return this.boundaries.stream().sorted().map(addr -> Long.toString(addr)).collect(Collectors.toList());
	}

	public static class RenderInfo implements Serializable {

		private static final long serialVersionUID = -1588370464143022477L;
		public List<InfoEntry> list;

		public RenderInfo() {

		}

		public static class SummaryInfo implements Serializable {
			private static final long serialVersionUID = 6209382019545417881L;
			public HashMap<String, Integer> binaryCloneCounterTarget = new HashMap<>();
			public HashMap<String, Integer> binaryCloneCounterSource = new HashMap<>();
			public HashMap<String, Integer> binarySize = new HashMap<>();
			public int total;
		}

		public static class InfoEntry implements Serializable {
			private static final long serialVersionUID = 7916141150918229675L;
			public String add;
			public String fn;
			public String fid;
			public HashMap<String, Double> mxs = new HashMap<>();

			public InfoEntry(FunctionCloneDetectionResultForWeb entry, String address, SummaryInfo info) {
				this.add = address;
				this.fn = entry.function.functionName;
				this.fid = entry.function.functionId;
				if (entry.clones.size() > 0) {
					for (FunctionCloneEntryForWeb clone : entry.clones) {
						mxs.compute(clone.binaryId,
								(k, v) -> v == null ? clone.similarity : (clone.similarity > v ? clone.similarity : v));
					}
				}
				mxs.keySet().stream()
						.forEach(key -> info.binaryCloneCounterTarget.compute(key, (k, v) -> v == null ? 1 : v + 1));
			}
		}

	}

	public void put(BinarySurrogate part) {
		Binary bin = part.toBinary();
		bin.functions.forEach(func -> {
			try {
				functionMap.put(Long.toString(func.functionId), mapper.writeValueAsBytes(new FunctionDataUnit(func)));
			} catch (Exception e) {
				logger.error("Failed to save " + part.name, e);
			}
		});
		addBinary(bin.binaryName, Long.toString(bin.binaryId));

	}

	public void put(FunctionCloneDataUnit unit, AsmObjectFactory factory, LocalJobProgress progress) {

		StageInfo stage = progress.nextStage(BinarySearchUnit.class, "Saving clones...");
		int page_size = 1000; // for now we hard coded that each page has 1000 functions.
		Queue<Long> boundaries = new ConcurrentLinkedQueue<Long>();
		AtomicLong counter = new AtomicLong(0);
		int total = unit.results.size();
		unit.results.stream().forEach(result -> {

			try {

				if (result.clones.size() < 1)
					logger.warn("Empty result for {} {}", result.function.functionName, result.function.binaryName);

				long currentCount = counter.getAndIncrement();
				stage.progress = currentCount * 1.0 / total;

				result.clones.sort((a, b) -> Double.compare(b.similarity, a.similarity));
				this.cloneDetails.put(result.function.functionId, mapper.writeValueAsBytes(result));

				FunctionDataUnit func = result.function;
				InfoEntry info = new InfoEntry(result, func.startAddress, this.summary);
				this.cloneInfoEntry.put(Long.parseLong(info.add), info);
				if (currentCount % page_size == 0)
					boundaries.add(Long.parseLong(info.add));

				result.clones.stream().forEach(clone -> {
					this.addBinary(clone.binaryName, clone.binaryId);
					String key = StringResources.JOINER_TOKEN_CSV.join(clone.binaryId, clone.functionId);
					this.binaryStats.put(key, true);
				});

			} catch (Exception e) {
				logger.error("Failed to save entry...", e);
			}
		});

		summary.total += unit.results.size();

		this.boundaries.addAll(boundaries);

		stage.complete();

	}

	public void fetchFunctionFlowFromRepository(long rid, AsmObjectFactory factory) {

		this.cloneDetails.values().parallelStream().map(bytes -> {
			try {
				return mapper.readValue(bytes, FunctionCloneDetectionResultForWeb.class);
			} catch (Exception e) {
				return null;
			}
		}).filter(val -> val != null).<Function>flatMap(result -> {
			HashSet<Long> fids = result.clones.stream().map(ent -> Long.parseLong(ent.functionId))
					.collect(Collectors.toCollection(HashSet::new));
			return factory.obj_functions.queryMultiple(rid, "functionId", fids).collect().stream();
		}).map(FunctionDataUnit::new).forEach(unit -> {
			try {
				this.functionMap.put(unit.functionId, mapper.writeValueAsBytes(unit));
			} catch (Exception e) {
				logger.error("Failed to save the function flow data.", e);
			}
		});
	}

	public void updateSummary(long rid, AsmObjectFactory factory, StageInfo stage, int blk_min, int blk_max) {
		try {

			HashSet<Long> bids = summary.binaryCloneCounterTarget.keySet().stream().map(key -> {
				if (key != null) {
					String key_s = StringResources.JOINER_TOKEN_CSV.join(key, Character.toString((char) (0)));
					String key_e = StringResources.JOINER_TOKEN_CSV.join(key, Character.toString((char) (255)));
					summary.binaryCloneCounterSource.put(key, this.binaryStats.subMap(key_s, key_e).size());
					Long lkey = Long.parseLong(key);
					return lkey;
				} else
					return null;
			}).filter(val -> val != null).collect(Collectors.toCollection(HashSet::new));
			stage.msg += " Total " + bids.size() + " bins.";
			Counter counter = new Counter();
			bids.stream().map(bid -> factory.obj_binaries.querySingle(rid, bid)).filter(bin -> bin != null)
					.forEach(binary -> {
						long funcs = 0;
						counter.inc();
						// Counter fCounter = new Counter();
						// if (binary.functionIds.size() > 1e4)
						funcs = binary.functionIds.size();
						// else
						// funcs = binary.functionIds.parallelStream().peek(fn -> {
						// fCounter.inc();
						// stage.progress = fCounter.percentage(binary.functionIds.size())
						// * counter.percentage(bids.size());
						// }).map(fid -> factory.obj_functions.querySingleBaisc(rid, fid)).filter(fn ->
						// fn != null)
						// .filter(fn -> fn.numBlocks >= blk_min && fn.numBlocks < blk_max).count();
						this.summary.binarySize.put(Long.toString(binary.binaryId), (int) funcs);
					});
			String smy = mapper.writeValueAsString(summary);
			properties.put(PROP_SUM, smy);
			properties.put(PROP_BOUN, mapper.writeValueAsString(this.boundaries));
		} catch (Exception e) {
			logger.error("Failed to update summary...", e);
		}

	}

	public void makeOffline(long rid, AsmObjectFactory factory, LocalJobProgress progress) {
		// construct function ids set to be retrieved

		HashSet<Long> fids = new HashSet<>();
		Reporter report = new Reporter(this.summary.total, logger);
		StageInfo stage = progress.nextStage(BinarySearchUnit.class,
				"Loading function IDs to be transferred from Cassandra to result file");
		this.cloneDetails.entrySet().parallelStream().forEach(ent -> {
			try {
				report.inc();
				stage.progress = report.prog();
				FunctionCloneDetectionResultForWeb result = mapper.readValue(ent.getValue(),
						FunctionCloneDetectionResultForWeb.class);
				result.clones.forEach(clone -> {
					fids.add(Long.parseLong(clone.functionId));
				});
			} catch (Exception e) {

			}
		});
		stage.complete();

		StageInfo stage2 = progress.nextStage(BinarySearchUnit.class,
				"Saving functions into result file.. {} unique funcs in total.", fids.size());

		Reporter report2 = new Reporter(fids.size(), logger);
		fids.parallelStream().map(fid -> {
			report2.inc();
			stage2.progress = report2.prog();
			return factory.obj_functions.querySingle(rid, "functionId", fid);
		}).filter(func -> func != null).map(FunctionDataUnit::new).forEach(unit -> {
			try {
				this.functionMap.put(unit.functionId, mapper.writeValueAsBytes(unit));
			} catch (Exception e) {
				logger.error("Failed to save the function flow data.", e);
			}
		});
		stage2.complete();

	}

	public void dumpAsJson(LocalJobProgress progress) throws Exception {

		Reporter report = new Reporter(this.summary.total, logger);
		StageInfo stage = progress.nextStage(BinarySearchUnit.class,
				"Dumping {} clone details...", this.summary.total);
		LineSequenceWriter writer = Lines.getLineWriter(this.file.getAbsolutePath() + ".json", false);
		this.cloneDetails.entrySet().stream().forEach(ent -> {
			try {
				report.inc();
				stage.progress = report.prog();
				FunctionCloneDetectionResultForWeb result = mapper.readValue(ent.getValue(),
						FunctionCloneDetectionResultForWeb.class);
				writer.writeLine(mapper.writeValueAsString(result));
			} catch (Exception e) {
				stage.msg = e.getMessage();
			}
		});
		writer.close();
		stage.complete();
	}

	@Override
	public void close() {
		if (db != null && !db.isClosed()) {
			db.close();
			try {
			} catch (Exception e) {
				logger.error("Failed to modify file attribute when closing temp db.", e);
			}
		}
	}

	public void generateDistributionFile() {

		ForkJoinPool.commonPool().execute(() -> {
			ArrayListMultimap<String, Double> counterMap = ArrayListMultimap.create();
			Reporter reporter = new Reporter(this.summary.total, logger);
			this.cloneDetails.values().stream().map(bytes -> {
				try {
					return mapper.readValue(bytes, FunctionCloneDetectionResultForWeb.class);
				} catch (Exception e) {
					return null;
				}
			}).filter(val -> val != null).forEach(result -> {
				HashMap<String, Double> localMap = new HashMap<>();
				result.clones.stream().forEach(clone -> {
					localMap.compute(clone.binaryName, (k, v) -> {
						if (v == null)
							return clone.similarity;
						if (v < clone.similarity)
							return clone.similarity;
						return v;
					});
				});
				localMap.forEach((k, v) -> counterMap.put(k, v));
				reporter.inc();
			});

			counterMap.keySet().forEach(key -> {
				List<Double> ls = counterMap.get(key);
				try {
					LineSequenceWriter writer = Lines.getLineWriter(key + "-dist.txt", false);
					ls.forEach(val -> writer.writeLineNoExcept(Double.toString(val)));
					writer.close();
				} catch (Exception e) {
					logger.error("Failed to write into file...");
				}

			});
		});

	}

	public BinarySearchUnit() {
	}

	public BinarySearchUnit(Long appId, File file) {

		this.file = file;
		this.db = DBMaker//
				.fileDB(file)//
				.transactionDisable()//
				.executorEnable()//
				.asyncWriteEnable()//
				.fileMmapEnableIfSupported()//
				.fileMmapCleanerHackEnable()//
				.closeOnJvmShutdown()//
				.make();

		this.functionMap = this.db.hashMap(FUNCMAP);
		this.cloneDetails = this.db.hashMap(CLONEDETAILS);
		this.properties = this.db.hashMap(PROPERTIES);
		this.binaryIdToNameMap = this.db.hashMap(BINIDNAME);
		this.binaryNameToIdMap = this.db.hashMap(BINNAMEID);
		this.cloneInfoEntry = this.db.treeMap(CLONEINFO);
		this.binaryStats = this.db.treeMap(CLONESTAT);
		{
			String strSum = this.properties.get(PROP_SUM);
			if (strSum == null)
				this.summary = new SummaryInfo();
			else
				try {
					this.summary = mapper.readValue(strSum, SummaryInfo.class);
				} catch (Exception e) {
					logger.error("Failed to read summary info from " + strSum, e);
					this.summary = new SummaryInfo();
				}
		}
		{
			String strBoun = this.properties.get(PROP_BOUN);
			if (strBoun == null)
				this.boundaries = new ArrayList<>();
			else
				try {
					this.boundaries = mapper.readValue(strBoun,
							mapper.getTypeFactory().constructCollectionType(List.class, Long.class));
				} catch (Exception e) {
					logger.error("Failed to read pagination boundaries info from " + strBoun, e);
					this.boundaries = new ArrayList<>();
				}
		}
		{
			String rid = this.properties.get(PROP_RID);
			if (appId != null) {
				this.appId = appId;
				this.properties.put(PROP_RID, Long.toString(appId));
			} else {
				try {
					this.appId = Long.parseLong(rid);
				} catch (Exception e) {
					logger.error("You have to set an app id when creating the clone unit file.", e);
				}
			}
		}

		// unit.generateDistributionFile();
		// unit.makeOffLine(Environment.globalObjectFactory, new
		// LocalJobProgress(-1, null));

	}

}
