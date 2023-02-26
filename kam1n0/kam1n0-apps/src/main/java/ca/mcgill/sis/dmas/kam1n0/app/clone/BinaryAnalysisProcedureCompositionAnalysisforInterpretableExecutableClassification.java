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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.app.util.FileInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.interpretableexecutableclassification.InterpretableExecutableClassificationApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.app.clone.interpretableexecutableclassification.InterpretableExecutableClassificationApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnitForInterpretableExecutableClassification;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.JobNameAnnotation;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobProcedure;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Cluster;

@JobNameAnnotation(jobName = "BinaryComposition")
public class BinaryAnalysisProcedureCompositionAnalysisforInterpretableExecutableClassification extends LocalDmasJobProcedure {

	private static Logger logger = LoggerFactory.getLogger(BinaryAnalysisProcedureCompositionAnalysis.class);
	public final static String KEY_FILES = "files";
	public final static String KEY_THRESHOLD = "threshold";
	public final static String KEY_TOP = "top";
	public final static String KEY_BLK_MAX = "blk_max";
	public final static String KEY_BLK_MIN = "blk_min";
	public final static String KEY_FILTER = "avoidSameBinary";

	@Override
	public void runProcedure(long appId, String appType, ApplicationResources res, String userName,
			LocalJobProgress progress, Map<String, Object> dataMap) {
		BinarySearchUnitForInterpretableExecutableClassification unit = null;
		try {

			//FileWriter fout = new FileWriter("time_consume.txt", true);
			DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss").withZone(ZoneId.systemDefault());
			LocalDateTime before_test = LocalDateTime.now();  
			Instant start_test = Instant.now();
			logger.info("begin Test:"+dtf.format(start_test)+"  \n");
			//fout.write("begin Test:"+dtf.format(start_test)+"  \n");
			double threshold = getDouble(KEY_THRESHOLD, dataMap, 0.5);
			int top = getInteger(KEY_TOP, dataMap, 10);
			int blk_min = getInteger(KEY_BLK_MIN, dataMap, 2);
			int blk_max = getInteger(KEY_BLK_MAX, dataMap, 1300);
			if (blk_max < 0)
				blk_max = Integer.MAX_VALUE;
			boolean avoidSameBinary = getBoolean(KEY_FILTER, dataMap, true);
			CloneSearchResources ress = (CloneSearchResources) res;
			InterpretableExecutableClassificationApplicationMeta meta = (InterpretableExecutableClassificationApplicationMeta)ress.meta;
			InterpretableExecutableClassificationApplicationConfiguration conf = (InterpretableExecutableClassificationApplicationConfiguration)meta.getInfo(appId).configuration;
			if (ress == null) {
				logger.error("Unmatched resource type {} but expected {}", res.getClass(), CloneSearchResources.class);
				progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class, "Invalid request");
				progress.complete();
			}

			StageInfo stage = null;
			String name = StringResources.STR_EMPTY;


            List<? extends Object> objs = getObj(KEY_FILES, dataMap);
            for(Object obj:objs)
            {
                BinarySurrogateMultipart parts = null;
                try {
                    if (obj instanceof BinarySurrogate) {
                        BinarySurrogate surrogate = (BinarySurrogate) obj;
                        File surrogateFile = new File(surrogate.name);
                        name = surrogateFile.getName();
                        stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
                                "Analysing binary " + name);
                        parts = surrogate.toMultipart();
                    } else if (obj instanceof File) {
                        File uploadedFile = (File) obj;
                        name = uploadedFile.getName();
                        stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
                                "Analysing binary " + name);
                        if (uploadedFile.getName().endsWith(".tagged") || uploadedFile.getName().endsWith(".json")) {
                            if (BinarySurrogateMultipart.check(uploadedFile)) {

                                parts = new BinarySurrogateMultipart(uploadedFile);
                            }
                            if (parts == null)
                                continue;
                        }
                        if (parts == null)
                            parts = ress.disassembleIntoMultiPart(uploadedFile, uploadedFile.getName(), progress);
                    } else {
                        stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class,
                                "Failed to analyze binary " + name + ": the upload file cant be found.");
                        return;
                    }
                } catch (Exception e) {
                    logger.error("Failed to diassemble binary file ", e);
                    continue;
                }

			stage.progress = 0.5;
			File resultFile = new File(Environment.getUserFolder(userName) + "/Composition-" + name + "-"
					+ StringResources.timeString() + ".kam");
			int blk_max_p = blk_max;


			InterpretableExecutableClassificationApplicationMeta appMeta = (InterpretableExecutableClassificationApplicationMeta)(ress.meta);
			List<Cluster> clusters = appMeta.clusterFactory.queryMultipleBaisc(appId).collect();
			unit = new BinarySearchUnitForInterpretableExecutableClassification(appId, resultFile);

			FileInfo info = FileInfo.readFileInfo(resultFile);
			info.preparing = true;
			info.task = this.getJobName();
			info.appType = appType;
			info.appId = appId;
			info.save();

			unit.setClusters(clusters);
			
			unit.get_class_map(meta.classFactory.queryMultipleBaisc(appId).collect());

			DmasFileOperations.setFileAttribute(resultFile, "preparing", true);
			DmasFileOperations.setFileAttribute(resultFile, "task", this.getJobName());
			DmasFileOperations.setFileAttribute(resultFile, "appType", appType);
			DmasFileOperations.setFileAttribute(resultFile, "appId", appId);

			int ind = 0;
			try {
			for (BinarySurrogate part : parts) {

				part.functions = part.functions.stream()
						.filter(func -> func.blocks.size() >= blk_min && func.blocks.size() < blk_max_p)
						.collect(Collectors.toCollection(ArrayList::new));
				if (progress.interrupted)
					throw new Exception("This job is being interrupted.. cancelling job.");

				ind++;
				stage.updateMsg("Saving " + "part " + (ind) + "/" + parts.size);
				unit.put(part);
				stage.msg = "Analysing binary " + name + " part " + (ind) + "/" + parts.size;
				FunctionCloneDataUnit cloneUnit = ress.detectFunctionClone(appId, part, threshold, top, avoidSameBinary,
						progress, false);
				unit.put(cloneUnit, ress.objectFactory, progress);

				stage.progress = ind * 0.5 / parts.size + 0.5;
			}
		    } catch (Exception e) {
         		logger.error("Failed to diassemble binary file ", e);
         		continue;
	        }
			stage.complete();

			info.preparing = false;
			info.save();
			stage = progress.nextStage(BinaryAnalysisProcedureCompositionAnalysisforInterpretableExecutableClassification.class, "Summarizing clone data..");
			unit.updateSummary(appId, ress.objectFactory,appMeta, userName, stage, name);
			unit.writeToDist(name);
			stage.complete();
			// unit.makeOffline(appId, ress.objectFactory, progress);
			unit.close();
			DmasFileOperations.setFileAttribute(resultFile, "preparing", false);

			}
			progress.complete();
			LocalDateTime after_test = LocalDateTime.now();  
			Instant end_test = Instant.now();
			logger.info("after test:"+dtf.format(after_test)+"    |    "+"Time taken: "+ Duration.between(start_test, end_test).toMillis() +" milliseconds"+"  \n");
			//fout.write("after test:"+dtf.format(after_test)+"    |    "+"Time taken: "+ Duration.between(start_test, end_test).toMillis() +" milliseconds"+"  \n");
			//fout.close();

		} catch (Exception e) {
			logger.error("Failed to process the " + getJobName() + " job from " + getJobName(), e);
			progress.nextStage(this.getClass(), "Failed to complete the job : " + e.getMessage());
			if (unit != null)
				unit.close();
		}

	}

}
