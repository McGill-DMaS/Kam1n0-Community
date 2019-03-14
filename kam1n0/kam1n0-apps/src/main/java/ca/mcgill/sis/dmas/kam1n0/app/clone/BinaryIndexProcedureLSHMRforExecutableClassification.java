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
package ca.mcgill.sis.dmas.kam1n0.app.clone;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BlockSurrogate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification.ClassClusterMeta;
import ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification.SoftwareClassMeta;
import ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification.ExecutableClassificationApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification.ExecutableClassificationApplicationConfiguration.ClusterModel;
import ca.mcgill.sis.dmas.kam1n0.app.clone.executableclassification.ExecutableClassificationApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.JobNameAnnotation;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobProcedure;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rep.ExecutableClassificationAsm2VecDetectorIntegration;
import java.time.format.DateTimeFormatter;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;    
@JobNameAnnotation(jobName = "BinaryIndexProcedure")
public class BinaryIndexProcedureLSHMRforExecutableClassification extends LocalDmasJobProcedure {

	public static final String KEY_FILES = "files";
	public final static String KEY_SIMILARITY_THRESHOLD = "similarity";
	public final static String KEY_DISTRIBUTION_THRESHOLD = "distribution";
	public static final String KEY_CLASS = "class";
	public final static String KEY_TRAIN = "train";
	public static final String KEY_CLUSTER = "cluster";
	public static final String KEY_N_EXECUTABLE_THRESHOLD = "n_executable";
	public static final String KEY_CLUSTER_METHOD = "cluster_method";

	private static Logger logger = LoggerFactory.getLogger(BinaryIndexProcedureLSHMR.class);

	@Override
	public void runProcedure(long appId, String appType, ApplicationResources res, String userName,
			LocalJobProgress progress, Map<String, Object> dataMap) {
		try {

			//FileWriter fout = new FileWriter("time_consume.txt", true);
			DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
			double similarity_threshold = getDouble(KEY_SIMILARITY_THRESHOLD, dataMap, 0.8);
			double distribution_threshold = getDouble(KEY_DISTRIBUTION_THRESHOLD, dataMap, 0.7);
			int n_exe_threshold = getInteger(KEY_N_EXECUTABLE_THRESHOLD, dataMap, 2);
			List<? extends Object> objs = getObj(KEY_FILES, dataMap);
			String softwareclass = getObj(KEY_CLASS, dataMap);
			boolean trainOrNot = getObj(KEY_TRAIN, dataMap);
			boolean clusterOrNot = getObj(KEY_CLUSTER, dataMap);
			ClusterModel clusterModel = getObj(KEY_CLUSTER_METHOD, dataMap);
			CloneSearchResources ress = (CloneSearchResources) res;
			if (ress == null) {
				logger.error("Unmatched resource type {} but expected {}", res.getClass(), CloneSearchResources.class);
				progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class, "Invalid request");
				progress.complete();
			}

			/**
			 * Not actually loaded into memory. Just meta-data.
			 */
			List<BinaryMultiParts> ls = objs.stream().map(obj -> {
				BinarySurrogateMultipart parts = null;
				if (obj instanceof File) {
					File file = (File) obj;
					if (file.getName().endsWith(".tagged") || file.getName().endsWith(".json"))
						if (BinarySurrogateMultipart.check(file)) {

							parts = new BinarySurrogateMultipart(file);
						}
					if (parts == null)
						try {
							// push_file here1 dissemble use a File object
							parts = ress.disassembleIntoMultiPart(file, file.getName(), progress);
						} catch (Exception e) {
							logger.error("Failed to diassembly binary file " + file.getName(), e);
							return null;
						}
				} else if (obj instanceof BinarySurrogate) {
					BinarySurrogate surrogate = (BinarySurrogate) obj;
					parts = surrogate.toMultipart();
				} else {
					logger.error("Unexpected type {}. Skipped.", obj.getClass().getName());
					return null;
				}
				BinarySurrogateMultipart partsFinal = parts;
				if (parts != null) {
					Iterable<Binary> itb = () -> new Iterator<Binary>() {
						Iterator<BinarySurrogate> ite = partsFinal.iterator();

						@Override
						public boolean hasNext() {
							return this.ite.hasNext();
						}

						@Override
						public Binary next() {
						try {
							Binary bin = this.ite.next().toBinaryWithFilters(func ->
							{
								if(func.blocks.size() > 2)
									return true;
								int n_ins = 0;
								for(BlockSurrogate block: func.blocks)
								{
									n_ins += block.src.size();
								}
								return n_ins > 4;
							});
							//Binary bin = this.ite.next().toBinaryWithFilters(func -> func.blocks.size() >= 5);
							return bin;
						    } catch (Exception e) {
						    	return null;
						    }
						}
					};

					// push_file here4
					return new BinaryMultiParts(itb, parts.size);
				}
				return null;
			}).filter(itb -> itb != null).collect(Collectors.toList());

			ExecutableClassificationAsm2VecDetectorIntegration detector = (ExecutableClassificationAsm2VecDetectorIntegration) (ress.detector.detector);


			//LocalDateTime before_train = LocalDateTime.now();
			//Instant start_train = Instant.now();
			//fout.write("begin train:"+dtf.format(before_train)+"  \n");
			detector.index(appId, ls, progress, trainOrNot);
			//Instant end_train = Instant.now();
			//LocalDateTime after_train = LocalDateTime.now();
			//fout.write("after train:"+dtf.format(after_train)+"    |    "+"Time taken: "+ Duration.between(start_train, end_train).toMillis() +" milliseconds"+"  \n");

				

	    	ExecutableClassificationApplicationMeta appMeta = (ExecutableClassificationApplicationMeta) (ress.meta);

	    	SoftwareClassMeta meta = appMeta.classFactory.querySingle(appId, softwareclass);
        
	    	if (meta == null) {
	    		meta = new SoftwareClassMeta(softwareclass);
	    	}
	    	
        
	    	for (BinaryMultiParts binmul : ls) {
	    		if(binmul==null)
	    			continue;
	    		Binary bin = binmul.iterator().next();
	    		if(bin==null)
	    			continue;
	    		meta.classBinaryList.add(bin.binaryId);
	    	}

	    	appMeta.classFactory.put(appId, meta);

			if (clusterOrNot) {
					
					if(!detector.trained)
						detector.index(appId, ls, progress, true);
				StageInfo stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
						"Clustering functions....");

				ExecutableClassificationApplicationConfiguration conf = (ExecutableClassificationApplicationConfiguration) appMeta
						.getInfo(appId).configuration;

				ArrayList<String> classes = conf.classes;

				Map<Long, String> functionIDtoClass = new HashMap<Long, String>();  //to remove
				Map<Long, String> binaryIDtoClass = new HashMap<Long, String>();
				Map<Long, Long> functionIDtobinID = new HashMap<Long, Long>();
				Map<Long, String> functionIDtoName = new HashMap<Long, String>();
				Map<String, Float> classNBinary = new HashMap<String, Float>();
				Map<Long, Double> binaryNClusters = new HashMap<Long, Double>();
				
				Map<Long, Map<String, Double>> functionClassDist = new HashMap<>();

				classes.stream().forEach(cls -> classNBinary.put(cls, 0.000001f));

				List<SoftwareClassMeta> softwareClassMetas = appMeta.classFactory.queryMultipleBaisc(appId).collect();
				for (SoftwareClassMeta met : softwareClassMetas) {
					classNBinary.compute(met.getClassName(), (k, v) -> v + met.classBinaryList.size());
					for (long binID : met.classBinaryList) {
						binaryIDtoClass.put(binID, met.className);
						binaryNClusters.put(binID, 0.);
						List<Function> funcList = appMeta.getFunctions(appId, binID);
						for (Function func : funcList) {
							functionIDtoClass.put(func.functionId, met.className); //to remove
							if(!functionClassDist.containsKey(func.functionId))
								functionClassDist.put(func.functionId, new HashMap<>());
							functionClassDist.get(func.functionId).put(met.className, 1.);
							functionIDtobinID.put(func.functionId, binID);
							functionIDtoName.put(func.functionId, func.functionName + " @ " + func.binaryName);
						}
					}
			}
				ArrayList<Cluster> clusters;

				if(clusterModel == ClusterModel.slink)
				{
					logger.info("Slink Cluster");
					LocalDateTime before_cluster = LocalDateTime.now();  
					Instant start_cluster = Instant.now();
					//fout.write("begin Slink Clustering:"+dtf.format(before_cluster)+"  \n");
					clusters = detector.SLINKcluster(appId, n_exe_threshold,
							classes, functionIDtoClass, functionIDtoName, functionIDtobinID, classNBinary, stage);
					Instant end_cluster = Instant.now();
					LocalDateTime after_cluster = LocalDateTime.now();
					//fout.write("after Slink  Clustering:"+dtf.format(after_cluster)+"    |    "+"Time taken: "+ Duration.between(start_cluster, end_cluster).toMillis() +" milliseconds"+"  \n");
				}
				else
				{
					logger.info("Union Cluster");
					LocalDateTime before_cluster = LocalDateTime.now();  
					Instant start_cluster = Instant.now();
					logger.info("begin Union Cluster:"+dtf.format(before_cluster)+"  \n");
					//fout.write("begin Union Cluster:"+dtf.format(before_cluster)+"  \n");
					 clusters = detector.cluster(appId, similarity_threshold,
					 distribution_threshold, classes, functionClassDist, functionIDtoName,
					 functionIDtobinID, classNBinary, stage);
					Instant end_cluster = Instant.now();
					LocalDateTime after_cluster = LocalDateTime.now();
					logger.info("after Union Cluster:"+dtf.format(after_cluster)+"    |    "+"Time taken: "+ Duration.between(start_cluster, end_cluster).toMillis() +" milliseconds"+"  \n");
					//fout.write("after Union Cluster:"+dtf.format(after_cluster)+"    |    "+"Time taken: "+ Duration.between(start_cluster, end_cluster).toMillis() +" milliseconds"+"  \n");
					
				}

				appMeta.clusterFactory.del(appId);

				Map<String, ClassClusterMeta> cls2clu = new HashMap<String, ClassClusterMeta>();

				classes.stream().forEach(cls -> {
					ClassClusterMeta clu = new ClassClusterMeta(cls);
					cls2clu.put(cls, clu);
				});

				clusters.stream().forEach(cluster -> {
					Map<Long, Boolean> counted = new HashMap<Long, Boolean>();
					ClassClusterMeta clu = cls2clu.get(cluster.className);
					clu.classClusterList.add(cluster.clusterName);
					appMeta.clusterFactory.put(appId, cluster);
					cluster.functionIDList.stream().forEach(id -> {
						long BID = functionIDtobinID.get(id);
						if (!counted.containsKey(BID)) {
							counted.put(BID, true);
							binaryNClusters.compute(BID, (k, v) -> v + cluster.classDist.get(binaryIDtoClass.get(BID)));
						}
					});
				});

				classes.stream().forEach(cls -> {
					double avg;
					SoftwareClassMeta clsMeta = appMeta.classFactory.querySingle(appId, cls);
					if (clsMeta == null)
						return;
					ClassClusterMeta clu = cls2clu.get(cls);
					clsMeta.classClusterList = clu.classClusterList;
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

				stage.complete();
			}
			
			List<Cluster> clusters = appMeta.clusterFactory.queryMultipleBaisc(appId).collect();


			Map<Long, String> binaryIDtoClass = new HashMap<Long, String>();
			Map<Long, String> binaryIDtoName = new HashMap<Long, String>();
			List<SoftwareClassMeta> softwareClassMetas = appMeta.classFactory.queryMultipleBaisc(appId).collect();
			for (SoftwareClassMeta met : softwareClassMetas) {
				for (long binID : met.classBinaryList) {
					binaryIDtoClass.put(binID, met.className);
					Binary bin = appMeta.platform.objectFactory.obj_binaries.querySingle(appId,binID);
					binaryIDtoName.put(binID, bin.binaryName);
					
				}
			}

			/*
			FileWriter fcluster = new FileWriter("f_cluster.txt", false);
			clusters.stream().forEach(cluster->{
				cluster.binaryIDList.stream().forEach(b->{try {
					fcluster.write(binaryIDtoName.get(b)+":"+binaryIDtoClass.get(b)+":"+cluster.clusterName+"\n");
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}});
			});
			fcluster.close();

			FileWriter fclass_dist = new FileWriter("cls_dist2.txt", false);
			clusters.stream().forEach(cluster->{
				try {
					fclass_dist.write("\n-------\n");
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				cluster.classDist.entrySet().stream().forEach(ent->{
					try {
						fclass_dist.write(ent.getKey()+" "+Double.toString(ent.getValue())+"\n");
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				});
			});
			fclass_dist.close();
			*/

			
			progress.complete();
    		//fout.close();

		} catch (Exception e) {
			logger.error("Failed to process the " + getJobName() + " job from " + userName, e);
			progress.nextStage(this.getClass(), "Failed to complete the job : " + e.getMessage());
			progress.complete();
		}
	}

}
