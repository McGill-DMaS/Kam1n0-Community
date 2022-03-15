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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.JobNameAnnotation;
import ca.mcgill.sis.dmas.kam1n0.app.scheduling.LocalDmasJobProcedure;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;

@JobNameAnnotation(jobName = "BinaryIndexProcedure")
public class BinaryIndexProcedureLSHMR extends LocalDmasJobProcedure {

	public static final String KEY_FILES = "files";

	private static Logger logger = LoggerFactory.getLogger(BinaryIndexProcedureLSHMR.class);

	@Override
	public void runProcedure(long appId, String appType, ApplicationResources res, String userName,
							 LocalJobProgress progress, Map<String, Object> dataMap) {
		try {
			List<? extends Object> objs = getObj(KEY_FILES, dataMap);
			CloneSearchResources ress = (CloneSearchResources) res;
			if (ress == null) {
				String errorMessage = MessageFormat.format("Unmatched resource type {} but expected {}", res.getClass(), CloneSearchResources.class);
				logger.error(errorMessage);
				progress.nextStage(BinaryAnalysisProcedureCompositionAnalysis.class, "Invalid request");
				progress.complete(errorMessage);
			}

			/**
			 * Not actually loaded into memory. Just meta-data.
			 */
			List<BinaryMultiParts> ls = objs.stream().map(obj -> {
				BinarySurrogateMultipart parts = null;
				if (obj instanceof File) {
					File file = (File) obj;
					if (file.getName().endsWith(".tagged") || file.getName().endsWith(".json"))
						if (BinarySurrogateMultipart.check(file))
							parts = new BinarySurrogateMultipart(file);
					if (parts == null)
						try {
							parts = ress.disassembleIntoMultiPart(file, file.getName(), progress);
						} catch (Exception e) {
							progress.errorMessage = MessageFormat.format("Failed to disassembly binary file " + file.getName(), e);
							logger.error(progress.errorMessage);
							return null;
						}
				} else if (obj instanceof BinarySurrogate) {
					BinarySurrogate surrogate = (BinarySurrogate) obj;
					parts = surrogate.toMultipart();
				} else {
					progress.errorMessage = MessageFormat.format("Unexpected type {}. Skipped.", obj.getClass().getName());
					logger.error(progress.errorMessage);
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
							return this.ite.next().toBinaryWithFilters(func -> func.blocks.size() > 0);
						}
					};
					return new BinaryMultiParts(itb, parts.size);
				}
				return null;
			}).filter(itb -> itb != null).collect(Collectors.toList());

			ress.indexBinary(appId, ls, progress);

			progress.complete(null);

		} catch (Exception e) {
			String errorMessage = MessageFormat.format("Failed to process the " + getJobName() + " job from " + userName, e);
			logger.error(errorMessage);
			System.out.println(e);
			e.printStackTrace();
			progress.nextStage(this.getClass(), "Failed to complete the job : " + e.getMessage());
			progress.complete(errorMessage);
		}
	}
}
