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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDetectionResultForWeb;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneEntryForWeb;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class FunctionCloneDetectorForWeb {

	public FunctionCloneDetector detector = null;
	private static Logger logger = LoggerFactory.getLogger(FunctionCloneDetectorForWeb.class);

	public FunctionCloneDetectorForWeb(FunctionCloneDetector detector) {
		this.detector = detector;
	}

	public ArrayList<FunctionCloneDetectionResultForWeb> detectClones(long rid, BinarySurrogate binary,
			double threashold, int topK, boolean avoidSameBinary, LocalJobProgress progress) throws Exception {

		StageInfo stage = progress.nextStage(FunctionCloneDetectorForWeb.class,
				"Detecting clones [" + binary.functions.size() + " funcs]");

		List<Function> funcs = binary.toFunctions();
		ArrayList<FunctionCloneDetectionResultForWeb> fullResults = new ArrayList<>();

		Counter counter = Counter.zero();
		long start = System.currentTimeMillis();
		String omString = stage.msg;
		Counter gate = new Counter();
		gate.inc(100);
//		ForkJoinPool pool = new ForkJoinPool(8);
//		pool.submit(() -> {

			List<FunctionCloneDetectionResultForWeb> ls = IntStream.range(0, funcs.size()).parallel()
					.mapToObj(ind -> {
						Function func = funcs.get(ind);

						if (progress.interrupted)
							return null;
						
//						try {
//							SparkInstance.checkAndWait();
//						} catch (Exception e1) {
//							logger.warn("Failed to check spark status.", e1);
//						}

						counter.inc();
						stage.progress = counter.getVal() * 1.0 / funcs.size();
						logger.info("{} queued {} bks named {}", StringResources.FORMAT_AR4D.format(stage.progress),
								func.blocks.size(), func.functionName);
						if(counter.getVal() > gate.getVal()) {
							gate.inc(100);
							double eta = (System.currentTimeMillis() - start) / stage.progress / 1000 / 60;
							double taken =  (System.currentTimeMillis() - start) / 1000 / 60;
							stage.msg = omString + " Taken " + StringResources.FORMAT_AR2D.format(taken) + " mins. Finishing in " + StringResources.FORMAT_AR2D.format(eta - taken) + " mins.";
						}

						try {
							return this.detectClones(rid, func, threashold, topK, avoidSameBinary);
						} catch (Exception e) {
							logger.error("Failed to detect clone for " + func.functionName, e);
							return null;
						}
					}).filter(re -> re != null).collect(Collectors.toList());
			fullResults.addAll(ls);
//		}).get();
//		pool.shutdownNow();

		stage.complete();

		if (progress.interrupted)
			throw new Exception("This job is being interrupted.. cancelling job.");

		//
		// for (Function function : binary.toFunctions()) {
		// FunctionCloneDetectionResultForWeb res = this.detectClones(function,
		// threashold);
		// if (res != null)
		// fullResults.add(res);
		// progress.currentProgress = count * 1.0 / total;
		// count++;
		// }

		return fullResults;
	}

	public FunctionCloneDetectionResultForWeb detectClones(long rid, Function function, double threadshold, int topK,
			boolean avoidSameBinary) throws Exception {
		FunctionCloneDetectionResultForWeb reslt = new FunctionCloneDetectionResultForWeb();
		detector.detectClonesForFunc(rid, function, threadshold, topK, avoidSameBinary).stream()
				.map(entry -> new FunctionCloneEntryForWeb(entry)).filter(entry -> entry.similarity >= threadshold)
				.forEach(reslt.clones::add);
		reslt.function = new FunctionDataUnit(function);
		return reslt;
	}

	public void indexFuncs(long rid, Binary bianry, LocalJobProgress progress) throws Exception {
		detector.index(rid, progress, bianry);
	}

	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join(detector.params(), "detectorWrapper=",
				this.getClass().getSimpleName());
	}

	public void init() throws Exception {
		detector.init();
	}

	public void close() throws Exception {
		detector.close();
	}

	public void clear(long rid) {
		this.detector.clear(rid);
	}

}
