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
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.ObjectWriter;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnitForClassification.RenderInfo.InfoEntry;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnitForClassification.RenderInfo.SummaryInfo;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnitForClassification.RenderInfo.ClassSummaryInfo;
import ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification.SoftwareClassMeta;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public class BinarySearchUnitForClassification implements Closeable {

	public File file;

	private static final String FUNCMAP = "FUNCMAP";
	private static final String CLONEDETAILS = "CLONEDETAILS";
	private static final String BINNAMEID = "BIN_NAMEID";
	private static final String BINIDNAME = "BIN_IDNAME";
	private static final String CLONEINFO = "CLONEINFO";
	private static final String CLUSTERCLONEINFO = "CLUSTERCLONEINFO";
	private static final String CLONESTAT = "CLONESTAT";
	private static final String PROPERTIES = "PROP";
	private static final String PROP_SUM = "PROP_SUM";
	private static final String PROP_BOUN = "PROP_BOUN";
	private static final String PROP_CLASS_SUM = "PROP_CLASS_SUM";
	private static final String PROP_RID = "PROP_RID";
	private static final String CLASSNAMEID = "CLASS_NAMEID";
	private static final String CLASSIDNAME = "CLASS_IDNAME";
	private static final String BINARYCLASS = "BINARY_CLASS";
	private static final String CLUSTERS = "CLUSTERS";
	private static final String FUNC2CLUSTER = "FUNC2CLUSTER";

	private transient static Logger logger = LoggerFactory.getLogger(BinarySearchUnitForClassification.class);

	//ChangedMarker
	protected transient DB db;

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
	public ConcurrentMap<String, String> classIdToNameMap;
	public ConcurrentMap<String, String> classNameToIdMap;
	public ConcurrentMap<String, String> binaryClass;
	public ConcurrentNavigableMap<String, Boolean> binaryStats;
	public ConcurrentMap<String, String> properties;
	private ConcurrentNavigableMap<Long, InfoEntry> cloneInfoEntry;
	private ConcurrentNavigableMap<Long, InfoEntry> clusterCloneInfoEntry;

	public List<Long> boundaries = new ArrayList<>();
	private ConcurrentMap<String, byte[]> clusters; 
	public ConcurrentMap<String, String> funcToCluster;
	

	public SummaryInfo summary = new SummaryInfo();
	public ClassSummaryInfo classSummary = new ClassSummaryInfo();

	public static class SummaryWrapper {
		public String fileName;
		public ClassSummaryInfo classSummary;
		public SummaryInfo summaryInfo;
		public Map<String, String> classIdToNameMap;
		public Map<String, String> classNameToIdMap;
		public Map<String, String> binaryIdToNameMap;
		public Map<String, String> binaryNameToIdMap;
	}

	public SummaryWrapper summarize() {
		SummaryWrapper wrapper = new SummaryWrapper();
		wrapper.classSummary = this.classSummary;
		wrapper.summaryInfo = this.summary;
		wrapper.fileName = this.file.getName();
		wrapper.classIdToNameMap = classIdToNameMap;
		wrapper.classNameToIdMap = classNameToIdMap;
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
	
	//inefficient
	public List<String> getBinaryList(String className) {
		
		ArrayList<String> result = new ArrayList<String>();
		

        Iterator<Map.Entry<String, String>> it = binaryClass.entrySet().iterator();
		while (it.hasNext()) {
		    Map.Entry<String, String> pair = it.next();
		    String binID = pair.getKey();
		    String binClass = pair.getValue();
		
		    if (binClass.equals(className)) {
		    	result.add(binID);
		    }
		}
		return result;
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

		List<String> to_filter = new ArrayList<String>();

		if (not_selected != null)
		{
			for(String cls:not_selected)
			{
				to_filter.addAll(getBinaryList(cls));
			}
			to_filter.stream().forEach(lg_val -> filter.add(lg_val));
		}
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

	
	/**
	 * If keyword-search is activated, ignore address range (no pagination).
	 * 
	 * @param addrStart
	 * @param addrEnd
	 * @param not_selected
	 * @param keyWord
	 * @return
	 */
	public RenderInfo getClusterCloneInfoList(long addrStart, long addrEnd, String[] not_selected, String keyWord) {
		RenderInfo rin = new RenderInfo();
		HashSet<String> filter = new HashSet<>();

		if (not_selected != null)
			Arrays.stream(not_selected).forEach(lg_val -> filter.add(lg_val));
		
		String tkw = keyWord.trim().toLowerCase();
		boolean keyword_search = !tkw.equals("*") && tkw.length() > 0;

		Map<Long, InfoEntry> map = null;
		if (keyword_search)
			map = clusterCloneInfoEntry;
		else
			map = clusterCloneInfoEntry.subMap(addrStart, true, addrEnd, false);
		//if (not_selected != null)
	    //	Arrays.stream(not_selected).forEach(lg_val -> logger.info(" : "+lg_val));

		rin.list = map.values().stream().filter(info -> !keyword_search || info.fn.toLowerCase().contains(tkw))
				.filter(info -> {
					if (not_selected == null)
						return true;
					info.mxs.keySet().removeAll(filter);
					return info.mxs.size() > 0;
				}).collect(Collectors.toList());

		return rin;
	}
	

	
	public FunctionCloneDetectionResultForWeb getClusterCloneDetail(String fid) {
		try {
			FunctionCloneDetectionResultForWeb result = mapper.readValue(this.cloneDetails.get(fid), FunctionCloneDetectionResultForWeb.class);
			
			result.clones = result.clones.stream().filter(clone->{
				if(!this.funcToCluster.containsKey(clone.functionId))
				{
					//shouldn't happen not in cluster:"+clone.functionName+" |from| "+ clone.binaryName);
					return false;
				}
				else
				{
					clone.functionName = clone.functionName + "@" + clone.binaryName + " || From Cluster: " + this.funcToCluster.get(clone.functionId);
					//logger.info(clone.functionName);
				    return true;
				}
			}).collect(Collectors.toCollection(ArrayList::new));
			
			return result;
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
					return new FunctionDataUnit(func, false, true);
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
			//binaryCloneCounterTarget: number of target file functions has a clone of the binary's function (each target function counts once)
			public HashMap<String, Integer> binaryCloneCounterTarget = new HashMap<>();
			//binaryCloneCounterSource: number of functions an indexed binary has that is clone of the target binary's function (each source function counts once)
			public HashMap<String, Integer> binaryCloneCounterSource = new HashMap<>();
			public HashMap<String, Integer> binarySize = new HashMap<>();
			public int total;
		}
		
		
		public static class ClassSummaryInfo implements Serializable {
			private static final long serialVersionUID = 6209382019545417882L;
			public HashMap<String, Integer> clusterCloneCounter = new HashMap<>();
			public HashMap<String, Integer> classCloneCounterTarget = new HashMap<>();
			public HashMap<String, Integer> classCloneCounterSource = new HashMap<>();
			public HashMap<String, Double> classAVGCluster = new HashMap<>();
			public HashMap<String, Integer> classSize = new HashMap<>();
			public HashMap<String, Integer> clusterSize = new HashMap<>();
			public HashMap<String, String> clusterToClass = new HashMap<>();
		    public Map<String, Map<String, Double>> classDist = new HashMap<>();
			public int total;
		}

		public static class InfoEntry implements Serializable {
			private static final long serialVersionUID = 7916141150918229675L;
			public String add;
			public String fn;
			public String fid;
			public HashMap<String, Double> mxs = new HashMap<>();

			public InfoEntry(FunctionCloneDetectionResultForWeb entry, String address, SummaryInfo info, ConcurrentMap<String, String> binaryClass) {
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
			
			public InfoEntry(FunctionCloneDetectionResultForWeb entry, String address, SummaryInfo info, ConcurrentMap<String, String> binaryClass, ConcurrentMap<String, String> funcToCluster) 
			{
				this.add = address;
				this.fn = entry.function.functionName;
				this.fid = entry.function.functionId;
				if (entry.clones.size() > 0) {
					for (FunctionCloneEntryForWeb clone : entry.clones) {
						if(funcToCluster.containsKey(clone.functionId))
						mxs.compute(funcToCluster.get(clone.functionId),
								(k, v) -> v == null ? clone.similarity : (clone.similarity > v ? clone.similarity : v));
					}
				}
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

		StageInfo stage = progress.nextStage(BinarySearchUnitForClassification.class, "Saving clones...");
		int total = unit.results.size();
		AtomicLong counter = new AtomicLong(0);
		int page_size = 1000; // for now we hard coded that each page has 1000 functions.
		HashMap <String, Boolean> functionDetected = new HashMap <String, Boolean>();
		HashMap <String, Boolean> functionClusterDetected = new HashMap <String, Boolean>();
		Queue<Long> boundaries = new ConcurrentLinkedQueue<Long>();
		unit.results.stream().forEach(result -> {
			try {

				if (result.clones.size() < 1)
					logger.warn("Empty result for {} {}", result.function.functionName, result.function.binaryName);
				long currentCount = counter.getAndIncrement();
				stage.progress = currentCount * 1.0 / total;

				result.clones.sort((a, b) -> Double.compare(b.similarity, a.similarity));
				this.cloneDetails.put(result.function.functionId, mapper.writeValueAsBytes(result));

				FunctionDataUnit func = result.function;
				InfoEntry info = new InfoEntry(result, func.startAddress, this.summary, this.binaryClass);
				this.cloneInfoEntry.put(Long.parseLong(info.add), info);
				if (currentCount % page_size == 0)
					boundaries.add(Long.parseLong(info.add));
				InfoEntry cluster_info = new InfoEntry(result, func.startAddress, this.summary, this.binaryClass, this.funcToCluster);
				if(!cluster_info.mxs.isEmpty())
					this.clusterCloneInfoEntry.put(Long.parseLong(info.add), cluster_info);
			
				result.clones.stream().forEach(clone -> {
					this.addBinary(clone.binaryName, clone.binaryId);
					String key = StringResources.JOINER_TOKEN_CSV.join(clone.binaryId, clone.functionId);
					this.binaryStats.put(key, true);
					if(this.funcToCluster.containsKey(clone.functionId)&&!functionDetected.containsKey(clone.functionId))
					{
						functionDetected.put(clone.functionId, true);
						String clu = this.funcToCluster.get(clone.functionId);
						this.classSummary.clusterCloneCounter.compute(clu, (k, v) -> v == null ? 1 :v+1);
					}
					
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

	public void updateSummary(long rid, AsmObjectFactory factory, StageInfo stage) {
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
			factory.obj_binaries.queryMultipleBaisc(rid, "binaryId", new ArrayList<>(bids)).collect()
					.forEach(binary -> {
						this.summary.binarySize.put(Long.toString(binary.binaryId), (int) binary.numFunctions);
					});
			String smy = mapper.writeValueAsString(summary);
			properties.put(PROP_SUM, smy);
			properties.put(PROP_BOUN, mapper.writeValueAsString(this.boundaries));
		} catch (Exception e) {
			logger.error("Failed to update summary...", e);
		}




        Iterator<Map.Entry<String, String>> it = binaryClass.entrySet().iterator();
		while (it.hasNext()) {
		    Map.Entry<String, String> pair = it.next();
		    String binID = pair.getKey();
		    String binClass = pair.getValue();
		    //logger.info("id:" + pair.getKey()+"  name: " + pair.getValue());
            if(this.summary.binaryCloneCounterSource.containsKey(binID))
            {
		        this.classSummary.classCloneCounterSource.compute(binClass, (k, v) -> v == null ? this.summary.binaryCloneCounterSource.get(binID) :v+this.summary.binaryCloneCounterSource.get(binID));
		        this.classSummary.classCloneCounterTarget.compute(binClass, (k, v) -> v == null ? this.summary.binaryCloneCounterTarget.get(binID) :v+this.summary.binaryCloneCounterTarget.get(binID));
            }
            else
            {
		        this.classSummary.classCloneCounterSource.compute(binClass, (k, v) -> v == null ? 0:v);
		        this.classSummary.classCloneCounterTarget.compute(binClass, (k, v) -> v == null ? 0:v);
            }
            int nFun = (int)(factory.obj_binaries.querySingle(rid,Long.parseLong(binID)).numFunctions);
		    this.classSummary.classSize.compute(binClass, (k, v) -> v == null ? nFun:v+nFun);
	    }
	    this.classSummary.total = this.summary.total;
	    try {
		String classsmy = mapper.writeValueAsString(this.classSummary);
		properties.put(PROP_CLASS_SUM, classsmy);
		} catch (Exception e) {
			logger.error("Failed to update summary...", e);
		}




/*
        Iterator<Map.Entry<String, String>> it = binaryClass.entrySet().iterator();
		while (it.hasNext()) {
		    Map.Entry<String, String> pair = it.next();
		    String binID = pair.getKey();
		    String binClass = pair.getValue();
		    System.out.println("id:" + pair.getKey()+"  name: " + pair.getValue());

            this.classSummary.classCloneCounterSource.compute(binClass, (k, v) -> v == null ? this.summary.binaryCloneCounterSource.get(binID) :v+this.summary.binaryCloneCounterSource.get(binID));
		    this.classSummary.classCloneCounterTarget.compute(binClass, (k, v) -> v == null ? this.summary.binaryCloneCounterTarget.get(binID) :v+this.summary.binaryCloneCounterTarget.get(binID));
		    this.classSummary.classSize.compute(binClass, (k, v) -> v == null ? this.summary.binarySize.get(binID) :v+this.summary.binarySize.get(binID));
	    }
	    this.classSummary.total = this.summary.total;
	    try {
		String classsmy = mapper.writeValueAsString(this.classSummary);
		properties.put(PROP_CLASS_SUM, classsmy);
		} catch (Exception e) {
			logger.error("Failed to update summary...", e);
		}
*/
	}



	public void writeToDist(String name)
	{
        try{
    		FileWriter fout = new FileWriter("class_dist.txt", true);
    		FileWriter fout2 = new FileWriter("cluster_class_dist.txt", true);
    		fout.write("-----------\n"+name+"\n");
    		double largest_sim = 0.;
    		String largest_cls = "";
    		HashMap<String, Double> clsNClusterClone = new HashMap<String, Double>();

    		this.classSummary.classAVGCluster.entrySet().stream().forEach(e->
    		{
    			clsNClusterClone.put(e.getKey(), 0.);
    		});

    		this.classSummary.clusterCloneCounter.entrySet().stream().forEach(e->
    		{
    			try {
					fout2.write("------\n");
				} catch (IOException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				}
    			this.classSummary.classDist.get(e.getKey()).entrySet().stream().forEach(ent->{
					try {
						fout2.write("class: "+ent.getKey()+"  weight:"+Double.toString(ent.getValue())+"\n");
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				});
    			this.classSummary.classDist.get(e.getKey()).entrySet().stream().forEach(ent->{if(clsNClusterClone.containsKey(ent.getKey()))clsNClusterClone.compute(ent.getKey(),(k,v)->v+ent.getValue());});
    			//clsNClusterClone.compute(this.classSummary.clusterToClass.get(e.getKey()), (k, v) -> v+this.classSummary.classDist.get(e.getKey()).get(k));
    		});
    		
    		for(Map.Entry<String, Double> e : this.classSummary.classAVGCluster.entrySet())
    		{

    			try {
    				double w = clsNClusterClone.get(e.getKey())/e.getValue();
					fout.write(e.getKey()+": "+Double.toString(1.0*clsNClusterClone.get(e.getKey())/e.getValue())+":"+Double.toString(clsNClusterClone.get(e.getKey()))+" "+Double.toString(e.getValue())+"\n");
				    if(w>largest_sim)
				    {
				    	largest_sim = w;
				    	largest_cls = e.getKey();
				    }
    			} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}  
    		}
    		fout.write("class: "+largest_cls+"\n");
    		fout.close();    
    		fout2.close();
           }
        catch(Exception e){e.printStackTrace();}   
	}
		

	public void makeOffline(long rid, AsmObjectFactory factory, LocalJobProgress progress) {
		// construct function ids set to be retrieved

		HashSet<Long> fids = new HashSet<>();
		Reporter report = new Reporter(this.summary.total, logger);
		StageInfo stage = progress.nextStage(BinarySearchUnitForClassification.class,
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

		StageInfo stage2 = progress.nextStage(BinarySearchUnitForClassification.class,
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

	public BinarySearchUnitForClassification() {
	}
	
	
	
	public void get_class_map(List<SoftwareClassMeta> class_list_RDD)
	{

		int ind = 0;
		
		for(SoftwareClassMeta met:class_list_RDD)
		{
			classIdToNameMap.put(Integer.toString(ind), met.className);
			classNameToIdMap.put(met.className, Integer.toString(ind));
			this.classSummary.classAVGCluster.put(met.className,met.getAverageNCluster());
			for(long biId: met.classBinaryList)
			{
				binaryClass.put(Long.toString(biId), Integer.toString(ind));
			}
			ind++;
		}
		
	}

	public void setClusters(List<Cluster> clusters)
	{
		clusters.stream().forEach(cluster->
		{
			this.classSummary.classDist.put(cluster.clusterName, cluster.classDist);
			try {
  	       		this.clusters.put(cluster.clusterName, mapper.writeValueAsBytes(cluster));
  	       } catch (Exception e) {
  	       	logger.error("Failed to save entry...", e);
	       }
     		cluster.functionIDList.stream().forEach(funcID->this.funcToCluster.put(Long.toString(funcID), cluster.clusterName)); 
     		this.classSummary.clusterSize.put(cluster.clusterName,cluster.functionIDList.size());
     		this.classSummary.clusterToClass.put(cluster.clusterName,cluster.className);
        });
	}

	public BinarySearchUnitForClassification(Long appId, File file) {
		this.file = file;
		this.db = DBMaker
				.fileDB(file)
				.executorEnable()
				.fileMmapEnableIfSupported()
				.closeOnJvmShutdown()
				.make();

		this.functionMap = this.db.hashMap(FUNCMAP).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.BYTE_ARRAY)
				.createOrOpen();
		this.cloneDetails = this.db.hashMap(CLONEDETAILS).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.BYTE_ARRAY)
				.createOrOpen();
		this.properties = this.db.hashMap(PROPERTIES).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.STRING)
				.createOrOpen();
		this.binaryIdToNameMap = this.db.hashMap(BINIDNAME).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.STRING)
				.createOrOpen();
		this.binaryNameToIdMap = this.db.hashMap(BINNAMEID).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.STRING)
				.createOrOpen();

		this.clusters = this.db.hashMap(CLUSTERS).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.BYTE_ARRAY)
				.createOrOpen();
		this.funcToCluster = this.db.hashMap(FUNC2CLUSTER).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.STRING)
				.create();
		this.classIdToNameMap = this.db.hashMap(CLASSIDNAME).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.STRING)
				.createOrOpen();
		this.classNameToIdMap = this.db.hashMap(CLASSNAMEID).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.STRING)
				.createOrOpen();
		this.binaryClass = this.db.hashMap(BINARYCLASS).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.STRING)
				.createOrOpen();

		this.clusterCloneInfoEntry = this.db.treeMap(CLUSTERCLONEINFO)
				.keySerializer(Serializer.LONG)
				.valueSerializer(Serializer.JAVA)
				.counterEnable()
				.createOrOpen();

		this.cloneInfoEntry = this.db.treeMap(CLONEINFO)
				.keySerializer(Serializer.LONG)
				.valueSerializer(Serializer.JAVA)
				.counterEnable()
				.createOrOpen();
		this.binaryStats = this.db.treeMap(CLONESTAT).keySerializer(Serializer.STRING)
				.valueSerializer(Serializer.BOOLEAN)
				.createOrOpen();

		String str = this.properties.get(PROP_SUM);
		String classstr = this.properties.get(PROP_CLASS_SUM);
		String rid = this.properties.get(PROP_RID);
		if (str == null)
			this.summary = new SummaryInfo();
		else
			try {
				this.summary = mapper.readValue(str, SummaryInfo.class);
			} catch (Exception e) {
				logger.error("Failed to read summary info from " + str, e);
				this.summary = new SummaryInfo();
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
		if (classstr == null)
			this.classSummary = new ClassSummaryInfo();
		else
			try {
				this.classSummary = mapper.readValue(classstr, ClassSummaryInfo.class);
			} catch (Exception e) {
				logger.error("Failed to read summary info from " + classstr, e);
				this.classSummary = new ClassSummaryInfo();
			}
		
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

		
		// unit.generateDistributionFile();
		// unit.makeOffLine(Environment.globalObjectFactory, new
		// LocalJobProgress(-1, null));

	}

}
