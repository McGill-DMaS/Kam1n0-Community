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
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.BinarySearchUnit;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.JobNameAnnotation;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobProcedure;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileInfo;
import ca.mcgill.sis.dmas.kam1n0.app.util.FileServingUtils;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;

@JobNameAnnotation(jobName = "BinaryCompositionDump")
public class DumpCompositionAnalysis extends LocalDmasJobProcedure {

	private static Logger logger = LoggerFactory.getLogger(DumpCompositionAnalysis.class);
	public final static String KEY_FILE = "file";

	@Override
	public void runProcedure(long appId, String appType, ApplicationResources res, String userName,
			LocalJobProgress progress, Map<String, Object> dataMap) {
		try {

			StageInfo stage = progress.nextStage(DumpCompositionAnalysis.class);

			BinarySearchUnit unit = getObj(KEY_FILE, dataMap);
			if (unit == null) {
				stage.updateMsg("Error: Failed to load file.");
				return;
			}

			stage.updateMsg("Dumping {}", unit.file.getName());
			unit.dumpAsJson(progress);
			stage.complete();
			progress.complete(null);

		} catch (Exception e) {
			String errorMessage = MessageFormat.format("Failed to process the " + getJobName() + " job from " + getJobName(), e);
			logger.error("Failed to process the " + getJobName() + " job from " + getJobName(), e);
			progress.nextStage(this.getClass(), "Failed to complete the job : " + e.getMessage());
			progress.complete(errorMessage);
		}
	}
}
