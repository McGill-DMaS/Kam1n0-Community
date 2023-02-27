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

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.kam1n0.app.clone.interpretableexecutableclassification.InterpretableExecutableClassificationApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BlockSurrogate;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.interpretableexecutableclassification.InterpretableExecutableClassificationClassClusterMeta;
import ca.mcgill.sis.dmas.kam1n0.app.clone.interpretableexecutableclassification.InterpretableExecutableClassificationClassMeta;
import ca.mcgill.sis.dmas.kam1n0.app.clone.interpretableexecutableclassification.InterpretableExecutableClassificationApplicationConfiguration.ClusterModel;
import ca.mcgill.sis.dmas.kam1n0.app.clone.interpretableexecutableclassification.InterpretableExecutableClassificationApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.JobNameAnnotation;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobProcedure;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Pattern;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rep.ExecutableClassificationAsm2VecDetectorIntegration;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

import java.time.format.DateTimeFormatter;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;

@JobNameAnnotation(jobName = "BinaryIndexProcedure")
public class BinaryIndexProcedureLSHMRforInterpretableExecutableClassification extends LocalDmasJobProcedure {

    public static final String KEY_FILES = "files";
    public final static String KEY_SIMILARITY_THRESHOLD = "similarity";
    public final static String KEY_DISTRIBUTION_THRESHOLD = "distribution";
    public final static String KEY_CLASS = "class";
    public final static String KEY_TRAIN = "train";
    public static final String KEY_TRAIN_CLASSIFIER = "train_classifier";
    public static final String KEY_CLUSTER_PATTERN = "cluster_pattern";
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
            final String softwareclass = getObj(KEY_CLASS, dataMap);
            boolean trainOrNot = getObj(KEY_TRAIN, dataMap);
            boolean clusterOrNot = getObj(KEY_CLUSTER, dataMap);
            boolean trainclassifier = getObj(KEY_TRAIN_CLASSIFIER, dataMap);
            boolean clusterpattern = getObj(KEY_CLUSTER_PATTERN, dataMap);
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

            List<String> softwareclasses = new ArrayList<String>();

            List<BinaryMultiParts> ls = objs.stream().map(obj -> {
                BinarySurrogateMultipart parts = null;
                if (obj instanceof File) {
                    File file = (File) obj;
                    if (file.getName().endsWith(".tagged") || file.getName().endsWith(".json")) {
                        if (BinarySurrogateMultipart.check(file)) {

                            parts = new BinarySurrogateMultipart(file);
                        }
                        if (parts == null)
                            return null;
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
                                    if (func.blocks.size() > 2)
                                        return true;
                                    int n_ins = 0;
                                    for (BlockSurrogate block : func.blocks) {
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
                    //File file = (File) obj;

                    //String[] d = file.getName().split("_", 10);
                    //softwareclasses.add("level_" + d[0]);


                    softwareclasses.add(softwareclass);


                    //This is for recognition of fine grained class
                    //String[] d = file.getName().split("_", 10);
                    //softwareclasses.add(d[0] + '_' + d[1]);

                    // push_file here4
                    return new BinaryMultiParts(itb, parts.size);
                }
                return null;
            }).filter(itb -> itb != null).collect(Collectors.toList());

            assert softwareclasses.size() == ls.size();

            ExecutableClassificationAsm2VecDetectorIntegration detector = (ExecutableClassificationAsm2VecDetectorIntegration) (ress.detector.detector);


            //LocalDateTime before_train = LocalDateTime.now();
            //Instant start_train = Instant.now();
            //fout.write("begin train:"+dtf.format(before_train)+"  \n");
            detector.index(appId, ls, progress, trainOrNot);
            //Instant end_train = Instant.now();
            //LocalDateTime after_train = LocalDateTime.now();
            //fout.write("after train:"+dtf.format(after_train)+"    |    "+"Time taken: "+ Duration.between(start_train, end_train).toMillis() +" milliseconds"+"  \n");


            InterpretableExecutableClassificationApplicationMeta appMeta = (InterpretableExecutableClassificationApplicationMeta) (ress.meta);
            int i = 0;
            for (BinaryMultiParts binmul : ls) {
                String cur_softwareclass = softwareclasses.get(i);
                i += 1;
                InterpretableExecutableClassificationClassMeta meta = appMeta.classFactory.querySingle(appId, cur_softwareclass);

                if (meta == null) {
                    meta = new InterpretableExecutableClassificationClassMeta(cur_softwareclass);
                }


                if (binmul == null)
                    continue;
                Binary bin = binmul.iterator().next();
                if (bin == null)
                    continue;
                meta.classBinaryList.add(bin.binaryId);
                appMeta.classFactory.put(appId, meta);
            }

/*
	    	InterpretableExecutableClassificationClassMeta meta = appMeta.classFactory.querySingle(appId, softwareclass);

	    	if (meta == null) {
	    		meta = new InterpretableExecutableClassificationClassMeta(softwareclass);
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
*/
            if (clusterOrNot) {

                if (!detector.trained)
                    detector.index(appId, ls, progress, true);
                StageInfo stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
                        "Clustering functions....");

                InterpretableExecutableClassificationApplicationConfiguration conf = (InterpretableExecutableClassificationApplicationConfiguration) appMeta
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

                List<InterpretableExecutableClassificationClassMeta> InterpretableExecutableClassificationClassMetas = appMeta.classFactory.queryMultipleBaisc(appId).collect();
                for (InterpretableExecutableClassificationClassMeta met : InterpretableExecutableClassificationClassMetas) {
                    classNBinary.compute(met.getClassName(), (k, v) -> v + met.classBinaryList.size());
                    for (long binID : met.classBinaryList) {
                        binaryIDtoClass.put(binID, met.className);
                        Map<String, Double> tmpmap = new HashMap<String, Double>();
                        binaryNClusters.put(binID, 0.);
                        classes.stream().forEach(cls -> tmpmap.put(cls, 0.00000));
                        List<Function> funcList = appMeta.getFunctions(appId, binID);
                        for (Function func : funcList) {
                            functionIDtoClass.put(func.functionId, met.className); //to remove
                            if (!functionClassDist.containsKey(func.functionId))
                                functionClassDist.put(func.functionId, new HashMap<>());
                            functionClassDist.get(func.functionId).put(met.className, 1.);
                            functionIDtobinID.put(func.functionId, binID);
                            functionIDtoName.put(func.functionId, func.functionName + " @ " + func.binaryName);
                        }
                    }
                }
                ArrayList<Cluster> clusters;

                if (clusterModel == ClusterModel.slink) {
                    logger.info("Slink Cluster");
                    LocalDateTime before_cluster = LocalDateTime.now();
                    Instant start_cluster = Instant.now();
                    //fout.write("begin Slink Clustering:"+dtf.format(before_cluster)+"  \n");
                    clusters = detector.SLINKcluster(appId, n_exe_threshold,
                            classes, functionIDtoClass, functionIDtoName, functionIDtobinID, classNBinary, stage);
                    Instant end_cluster = Instant.now();
                    LocalDateTime after_cluster = LocalDateTime.now();
                    //fout.write("after Slink  Clustering:"+dtf.format(after_cluster)+"    |    "+"Time taken: "+ Duration.between(start_cluster, end_cluster).toMillis() +" milliseconds"+"  \n");
                } else {
                    logger.info("Union Cluster");
                    LocalDateTime before_cluster = LocalDateTime.now();
                    Instant start_cluster = Instant.now();
                    logger.info("begin Union Cluster:" + dtf.format(before_cluster) + "  \n");
                    //fout.write("begin Union Cluster:"+dtf.format(before_cluster)+"  \n");


                    int klsh = ((InterpretableExecutableClassificationApplicationConfiguration) appMeta.getInfo(appId).configuration).kMax;
                    int llsh = ((InterpretableExecutableClassificationApplicationConfiguration) appMeta.getInfo(appId).configuration).l;
                    int maxiFunc = ((InterpretableExecutableClassificationApplicationConfiguration) appMeta.getInfo(appId).configuration).maxiFunc;
                    boolean uselsh = ((InterpretableExecutableClassificationApplicationConfiguration) appMeta.getInfo(appId).configuration).uselsh;


                    clusters = detector.cluster(appId, similarity_threshold,
                            distribution_threshold, classes, functionClassDist, functionIDtoName,
                            functionIDtobinID, classNBinary, klsh, llsh, maxiFunc, uselsh, stage);
                    Instant end_cluster = Instant.now();
                    LocalDateTime after_cluster = LocalDateTime.now();
                    logger.info("after Union Cluster:" + dtf.format(after_cluster) + "    |    " + "Time taken: " + Duration.between(start_cluster, end_cluster).toMillis() + " milliseconds" + "  \n");
                    //fout.write("after Union Cluster:"+dtf.format(after_cluster)+"    |    "+"Time taken: "+ Duration.between(start_cluster, end_cluster).toMillis() +" milliseconds"+"  \n");

                }

                appMeta.clusterFactory.del(appId);


                Map<String, InterpretableExecutableClassificationClassClusterMeta> cls2clu = new HashMap<String, InterpretableExecutableClassificationClassClusterMeta>();

                classes.stream().forEach(cls -> {
                    InterpretableExecutableClassificationClassClusterMeta clu = new InterpretableExecutableClassificationClassClusterMeta(cls);
                    cls2clu.put(cls, clu);
                });

                clusters.stream().forEach(cluster -> {
                    Map<Long, Boolean> counted = new HashMap<Long, Boolean>();
                    InterpretableExecutableClassificationClassClusterMeta clu = cls2clu.get(cluster.className);
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
                    InterpretableExecutableClassificationClassMeta clsMeta = appMeta.classFactory.querySingle(appId, cls);
                    if (clsMeta == null)
                        return;
                    InterpretableExecutableClassificationClassClusterMeta clu = cls2clu.get(cls);
                    clsMeta.classClusterList = clu.classClusterList;
                    //String avgs = "avg";
                    //average
                    //avg = clsMeta.classBinaryList.stream().map(BID -> binaryNClusters.get(BID)).reduce(0., Double::sum)
                    //		/ clsMeta.classBinaryList.size();

                    //median
                    //avgs = "median";
                    List<Double> ncls = clsMeta.classBinaryList.stream().map(BID -> binaryNClusters.get(BID)).collect(Collectors.toList());
                    Collections.sort(ncls);
                    avg = ncls.get(ncls.size() / 2);


                    clsMeta.averageNCluster = avg;
                    appMeta.classFactory.put(appId, clsMeta);
                });

                stage.complete();
            }


            if (trainclassifier) {

                StageInfo stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
                        "Training classifier....");
                InterpretableExecutableClassificationApplicationConfiguration conf = (InterpretableExecutableClassificationApplicationConfiguration) appMeta
                        .getInfo(appId).configuration;

                double threshold = 0.5;

                ArrayList<String> classes = conf.classes;


                Map<Long, String> binaryIDtoClass = new HashMap<Long, String>();
                Map<Long, String> binarytoName = new HashMap<Long, String>();
                Map<String, Integer> classtoID = new HashMap<String, Integer>();
                Map<Long, Map<Integer, Boolean>> binaryClusters = new HashMap<Long, Map<Integer, Boolean>>();
                Map<Long, Integer> funtoClusterID = new HashMap<Long, Integer>();
                Map<String, Integer> clustertoID = new HashMap<String, Integer>();


                List<Cluster> clusters = appMeta.clusterFactory.queryMultipleBaisc(appId).collect();
                int clusterID = 0;
                for (Cluster cluster : clusters) {
                    //2020-01-17
                    clustertoID.put(cluster.clusterName, clusterID);
                    for (Long binID : cluster.binaryIDList) {
                        if (!binaryClusters.containsKey(binID)) {
                            Map<Integer, Boolean> tmpmap = new HashMap<Integer, Boolean>();
                            tmpmap.put(clusterID, true);
                            binaryClusters.put(binID, tmpmap);
                        } else {
                            Map<Integer, Boolean> tmpmap = binaryClusters.get(binID);
                            tmpmap.put(clusterID, true);
                        }
                    }

                    for (Long funcID : cluster.functionIDList) {
                        funtoClusterID.put(funcID, clusterID);
                    }

                    clusterID += 1;
                }
                String trainPath = Environment.getAppFolder(appId) + "/"+"train.csv";
                FileWriter fout = new FileWriter(trainPath, false);
                FileWriter fout_train_order = new FileWriter(Environment.getAppFolder(appId) + "/"+"train_order.csv", false);

                int classID = 0;
                int n_features = clusters.size();
                System.out.println("number of features:" + Integer.toString(n_features));
                List<InterpretableExecutableClassificationClassMeta> InterpretableExecutableClassificationClassMetas = appMeta.classFactory.queryMultipleBaisc(appId).collect();
                for (InterpretableExecutableClassificationClassMeta met : InterpretableExecutableClassificationClassMetas) {
                    classtoID.put(met.className, classID);
                    for (long binID : met.classBinaryList) {
                        Binary bin = appMeta.getBinary(appId, binID);
                        binarytoName.put(binID, bin.binaryName);
                        binaryIDtoClass.put(binID, met.className);
                        fout.write(Integer.toString(classID));
                        fout_train_order.write(bin.binaryName);
                        if (binaryClusters.containsKey(binID)) {
                            Map<Integer, Boolean> binfeature = binaryClusters.get(binID);
                            fout_train_order.write(" " + Integer.toString(binfeature.size()));
                            for (int cur_f = 0; cur_f < n_features; cur_f++) {
                                if (binfeature.containsKey(cur_f)) {
                                    fout.write(",1");
                                } else {
                                    fout.write(",0");
                                }
                            }
                        } else {
                            fout_train_order.write(" 0");
                            for (int cur_f = 0; cur_f < n_features; cur_f++) {
                                fout.write(",0");
                            }
                        }
                        fout.write("\n");
                        fout_train_order.write("\n");

                    }
                    classID++;
                }


                fout.close();
                fout_train_order.close();

                JSONObject binarytoNamejson = new JSONObject();
                binarytoNamejson.putAll(binarytoName);
                try (FileWriter file = new FileWriter(Environment.getAppFolder(appId) + "/"+"binarytoName.json")) {
                    file.write(binarytoNamejson.toJSONString());
                }

                JSONObject classtoIDjson = new JSONObject();
                classtoIDjson.putAll(classtoID);
                try (FileWriter file = new FileWriter(Environment.getAppFolder(appId) + "/"+"classtoID.json")) {
                    file.write(classtoIDjson.toJSONString());
                }
                JSONObject clustertoIDjson = new JSONObject();
                clustertoIDjson.putAll(clustertoID);
                try (FileWriter file = new FileWriter(Environment.getAppFolder(appId) + "/"+"clustertoID.json")) {
                    file.write(clustertoIDjson.toJSONString());
                }
                JSONObject funtoClusterIDjson = new JSONObject();
                funtoClusterIDjson.putAll(funtoClusterID);
                try (FileWriter file = new FileWriter(Environment.getAppFolder(appId) + "/"+"funtoClusterID.json")) {
                    file.write(funtoClusterIDjson.toJSONString());
                }

                int nclasses = classtoID.size();


                int seed = 123;
                double learningRate = 0.0001;
                int batchSize = 64;
                int nEpochs = 200;

                int numInputs = n_features;
                int numOutputs = nclasses;
                int numHiddenNodes = 20;
                ArrayList<String> hiddendims = conf.getHiddendims();
                String hidDimString = "";

                for (String s : hiddendims)
                {
                    hidDimString += s + ",";
                }

                Map<String,String> hypara = new HashMap<String,String>();
                hypara.put("feature_length",Integer.toString(numInputs));
                hypara.put("hiddendims",hidDimString);
                hypara.put("n_class",Integer.toString(numOutputs));
                hypara.put("n_epoch",Integer.toString(conf.getMaxEpochs()));
                hypara.put("batch_size",Integer.toString(256));  //TODO
                hypara.put("learning_rate",Float.toString(0.001f));  //TODO


                JSONObject hyparajson = new JSONObject();
                hyparajson.putAll(hypara);
                try (FileWriter file = new FileWriter(Environment.getAppFolder(appId) + "/"+"hypara.json")) {
                    file.write(hyparajson.toJSONString());
                }

                File script = KamResourceLoader.loadFile("iffnn.py");
                String[] arg = null;
                arg = new String[] { "python", script.getName(), "--task", "train", "--hyper", Environment.getAppFolder(appId) + "/"+"hypara.json", "--train", trainPath, "--save", Environment.getAppFolder(appId) + "/model.pkl"};

                // System.out.println(StringResources.JOINER_TOKEN.join(arg));

                ProcessBuilder pBuilder = new ProcessBuilder(arg);
                pBuilder.directory(script.getParentFile());
                Process p = pBuilder.start();
                p.waitFor();
                //FFN ffn = new FFN(numInputs,hiddendims,numOutputs, Environment.getAppFolder(appId) + "/"+"DLClassifier.zip");
                //ffn.train(trainPath, conf.getMaxEpochs());
                stage.complete();
            }


            if (clusterpattern) {

                StageInfo stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
                        "Mining cluster patterns....");
                appMeta.patternFactory.del(appId);
                logger.info("begin to write function call");
                try (FileWriter fcall = new FileWriter(Environment.getAppFolder(appId) + "/"+"funcalls.json")) {
                    //try (FileWriter file = new FileWriter(Environment.getAppFolder(appId) + "/"+"funtoClusterID.json")) {
                        List<Binary> binaries = appMeta.getBinaries(appId);
                        int nbin = binaries.size();
                        int ii=0;
                        for (Binary bin : binaries) {
                            stage.progress = 0.5 * ii / nbin;
                            ii+=1;
                            logger.info(Integer.toString(ii)+" "+Integer.toString(nbin));
                            fcall.write(Long.toString(bin.binaryId)+":\n");
                            Binary tmp = appMeta.getBinary(appId,bin.binaryId);
                            List<Function> functions = appMeta.platform.objectFactory.obj_functions.queryMultiple(appId, "functionId",tmp.functionIds).collect().stream()
                                    .collect(Collectors.toList());
                            for (Function func : functions) {
                                fcall.write(Long.toString(func.functionId) +";\n");
                                for(Long called : func.callingFunctionIds)
                                {
                                    fcall.write(Long.toString(called) +"\n");
                                }
                            }
                            //for (Long funcId : tmp.functionIds) {
                            //    Function func = appMeta.platform.getFunction(appId,funcId);
                            //    fcall.write(Long.toString(funcId) +";\n");
                            //    for(Long called : func.callingFunctionIds)
                            //    {
                            //        fcall.write(Long.toString(called) +"\n");
                            //    }
                            //}
                        }
                    //}
                }
                catch(Exception e) {
                    System.out.println(e.toString());
                    e.printStackTrace();
                }
                List<Cluster> clusters = appMeta.clusterFactory.queryMultipleBaisc(appId).collect();
                Map<String,Cluster> namCluster = new HashMap<String, Cluster>();
                clusters.stream().forEach(cluster -> {
                    namCluster.put(cluster.clusterName,cluster);
                });


                logger.info("begin to write cluster composition");
                try (FileWriter fclusfuncs = new FileWriter(Environment.getAppFolder(appId) + "/"+"clusterfuncs.json")) {
                    int nclusters = clusters.size();
                    int ii=0;
                    for(Cluster cluster:clusters)
                    {
                        stage.progress = 0.5 + ii / nclusters;
                        ii+=1;
                        fclusfuncs.write(cluster.clusterName+":\n");
                        for(Long func : cluster.functionIDList)
                        {
                            fclusfuncs.write(Long.toString(func) +"\n");
                        }
                    }

                }
                catch(Exception e) {
                    System.out.println(e.toString());
                    e.printStackTrace();
                }
                logger.info("begin next");
                stage.complete();



                InterpretableExecutableClassificationApplicationConfiguration conf = (InterpretableExecutableClassificationApplicationConfiguration) appMeta
                        .getInfo(appId).configuration;

                logger.info("begin to recognize cluster patterns");
                stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
                        "recognizing cluster patterns....");
                File script = KamResourceLoader.loadFile("pr.py");
                String[] arg = null;
                if(conf.patternRecognitionMethod== InterpretableExecutableClassificationApplicationConfiguration.PatternRecognitionMethod.FrequentItemsetMining)
                    arg = new String[] { "python", script.getName(), "--method", "fis","--nsup",Integer.toString(conf.minsupport), "--root", Environment.getAppFolder(appId), "--name","funcalls.json"};
                else
                    arg = new String[] { "python", script.getName(), "--method", "spectrum","--npat",Integer.toString(conf.nPatterns), "--root", Environment.getAppFolder(appId), "--name","funcalls.json"};

                logger.info("script.getName():  "+script.getName());
                logger.info("Environment.getAppFolder(appId):  "+Environment.getAppFolder(appId));
                ProcessBuilder pBuilder = new ProcessBuilder(arg);
                pBuilder.directory(script.getParentFile());
                Process p = pBuilder.start();
                p.waitFor();
                logger.info("Cluster patterns recognized");
                stage.complete();
                String line;

                String call_fp = Environment.getAppFolder(appId)+"/funcalls.json_cluster_calls.txt";
                Map<String, Map<String,Integer>> clscall = new HashMap<String, Map<String,Integer>>();

                try (BufferedReader br = new BufferedReader(
                        new FileReader(call_fp))) {
                    while ((line = br.readLine()) != null) {
                        String[] split = line.split(" ");
                        String caller = split[0];
                        String callee = split[1];
                        int ncall = Integer.parseInt(split[2]);
                        if(!clscall.containsKey(caller)){
                            clscall.put(caller,new HashMap<String,Integer>());
                        }
                        clscall.get(caller).put(callee,ncall);

                    }



                } catch (IOException e) {
                    e.printStackTrace();
                }


                String res_fp = Environment.getAppFolder(appId)+"/funcalls.json_patterns.txt";

                Map<String, Set<String>> cls2pats = new HashMap<String, Set<String>>();
                ArrayList<String> classes = conf.classes;
                try (BufferedReader br = new BufferedReader(
                        new FileReader(res_fp))) {
                    List<String> pattern = new ArrayList<String>();
                    Map<String, Integer> patNcluster = new HashMap<String, Integer>();
                    classes.stream().forEach(cls -> {
                        cls2pats.put(cls,new HashSet<String>());
                    });
                    Map<String, Map<String,Integer>> tmp_clscall = new HashMap<String, Map<String,Integer>>();

                    while ((line = br.readLine()) != null) {
                        if (line.contains(":")){
                            if(pattern.size()>0){
                                Map<String, Integer> clsNcluster = new HashMap<String, Integer>();
                                for(String cluster : pattern){
                                    String[] split = cluster.split("_");
                                    if(!clsNcluster.containsKey(split[0])){
                                        clsNcluster.put(split[0],1);
                                    }else{
                                        clsNcluster.put(split[0],clsNcluster.get(split[0])+1);
                                    }
                                }
                                String cls="";
                                int n=0;

                                for (Map.Entry<String, Integer> entry : clsNcluster.entrySet()) {
                                    String cur_cls = entry.getKey();
                                    int ncls = entry.getValue();
                                    if(ncls>n)
                                    {
                                        cls=cur_cls;
                                        n=ncls;
                                    }
                                }
                            if(!patNcluster.containsKey(cls)){
                                patNcluster.put(cls,0);
                            }
                            patNcluster.put(cls,patNcluster.get(cls)+1);
                            String patternName = cls+"_pattern"+Integer.toString(patNcluster.get(cls));
                            Pattern pat = new Pattern(patternName,cls,tmp_clscall);
                            logger.info(patternName);
                            pattern.stream().forEach(cluster->{
                                namCluster.get(cluster).patternID =patternName;
                                pat.addCluster(cluster);
                            });

                            for (Map.Entry<String, Map<String,Integer>> entry : pat.clscall.entrySet()) {
                                String key_cluster = entry.getKey();
                                Map<String,Integer> val_clusters = entry.getValue();
                                if(val_clusters!=null) {
                                    List<String> toremove = new ArrayList<>();
                                    for (String cluster : val_clusters.keySet()) {
                                        if (!pat.clusterList.contains(cluster)) {
                                            toremove.add(cluster);
                                            //val_clusters.remove(cluster);
                                        }
                                    }
                                    toremove.stream().forEach(cluster->val_clusters.remove(cluster));
                                }
                                //if(val_clusters!=null)
                                //val_clusters.keySet().stream().filter(cluster->{return pat.clusterList.contains(cluster);}).forEach(cluster->{val_clusters.remove(cluster);});
                                // ...
                            }


                            cls2pats.get(cls).add(pat.patternID);
                            appMeta.patternFactory.put(appId, pat);
                            pattern = new ArrayList<String>();
                            tmp_clscall = new HashMap<String, Map<String,Integer>>();
                            logger.info("=======\nnew pattern");

                            }
                        }else{
                            pattern.add(line);
                            tmp_clscall.put(line,clscall.get(line));
                            //logger.info(line);
                        }

                        }

                    if(pattern.size()>0){
                        Map<String, Integer> clsNcluster = new HashMap<String, Integer>();
                        for(String cluster : pattern){
                            String[] split = cluster.split("_");
                            if(!clsNcluster.containsKey(split[0])){
                                clsNcluster.put(split[0],1);
                            }else{
                                clsNcluster.put(split[0],clsNcluster.get(split[0])+1);
                            }
                        }
                        String cls="";
                        int n=0;

                        for (Map.Entry<String, Integer> entry : clsNcluster.entrySet()) {
                            String cur_cls = entry.getKey();
                            int ncls = entry.getValue();
                            if(ncls>n)
                            {
                                cls=cur_cls;
                                n=ncls;
                            }
                        }
                        if(!patNcluster.containsKey(cls)){
                            patNcluster.put(cls,0);
                        }
                        patNcluster.put(cls,patNcluster.get(cls)+1);
                        String patternName = cls+"_pattern"+Integer.toString(patNcluster.get(cls));
                        Pattern pat = new Pattern(patternName,cls,tmp_clscall);
                        logger.info(patternName);
                        pattern.stream().forEach(cluster->{
                            namCluster.get(cluster).patternID =patternName;
                            pat.addCluster(cluster);
                        });


                        for (Map.Entry<String, Map<String,Integer>> entry : pat.clscall.entrySet()) {
                            String key_cluster = entry.getKey();
                            System.out.println("key_cluster: "+key_cluster);
                            Map<String,Integer> val_clusters = entry.getValue();
                            if(val_clusters!=null) {
                                List<String> toremove = new ArrayList<>();
                                for (String cluster : val_clusters.keySet()) {
                                    if (!pat.clusterList.contains(cluster)) {
                                        toremove.add(cluster);
                                        //val_clusters.remove(cluster);
                                    }
                                }
                                toremove.stream().forEach(cluster->val_clusters.remove(cluster));
                            }
                            //if(val_clusters!=null)
                            //val_clusters.keySet().stream().filter(cluster->{return pat.clusterList.contains(cluster);}).forEach(cluster->{val_clusters.remove(cluster);});
                            // ...
                        }


                        cls2pats.get(cls).add(pat.patternID);
                        appMeta.patternFactory.put(appId, pat);
                        pattern = new ArrayList<String>();
                        logger.info("=======\nnew pattern");
                    }



                    clusters.stream().forEach(cluster -> {
                        appMeta.clusterFactory.put(appId, cluster);});

                    classes.stream().forEach(cls -> {
                        InterpretableExecutableClassificationClassMeta clsMeta = appMeta.classFactory.querySingle(appId, cls);
                        clsMeta.classPatternList = cls2pats.get(cls);
                        appMeta.classFactory.put(appId, clsMeta);
                    });



                } catch (IOException e) {
                    e.printStackTrace();
                }


            }


            progress.complete();
            //fout.close();

        } catch (Exception e) {
            logger.error("Failed to process the " + getJobName() + " job from " + userName, e);
            progress.nextStage(this.getClass(), "Failed to complete the job : " + e.getMessage());
            progress.complete();
        }
    }

}
