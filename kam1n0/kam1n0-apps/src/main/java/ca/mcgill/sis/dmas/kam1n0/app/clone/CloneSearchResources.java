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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDataUnit;
import ca.mcgill.sis.dmas.kam1n0.app.clone.adata.FunctionCloneDetectionResultForWeb;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.DisassemblyFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.RawFunctionParser;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;

public class CloneSearchResources extends ApplicationResources {

	private static Logger logger = LoggerFactory.getLogger(CloneSearchResources.class);

	public DisassemblyFactory disassemblyFactory;
	public AsmObjectFactory objectFactory;
	public FunctionCloneDetectorForWeb detector;
	public RawFunctionParser parser;
	public ApplicationMeta meta;

	public FunctionCloneDataUnit detectFunctionClone(long appId, Function function, double threadshold, int topK,
			boolean avoidSameBinary, boolean generateCloneGraph) throws Exception {

		long start = System.currentTimeMillis();

		ArrayList<FunctionCloneDetectionResultForWeb> results = new ArrayList<>();

		FunctionCloneDetectionResultForWeb res = detector.detectClones(appId, function, threadshold, topK,
				avoidSameBinary);
		if (res != null)
			results.add(res);

		logger.info("Taken {} ms", System.currentTimeMillis() - start);

		FunctionCloneDataUnit callBack = new FunctionCloneDataUnit(results);
		callBack.takenTime = System.currentTimeMillis() - start;
		if (generateCloneGraph)
			callBack.generateCloneGraph();
		return callBack;
	}

	public FunctionCloneDataUnit detectFunctionClone(long appId, BinarySurrogate surrogate, double threshold, int topK,
			boolean avoidSameBinary, LocalJobProgress progress, boolean generateCloneGraph) throws Exception {

		long start = System.currentTimeMillis();

		logger.info("Querying {} functions.", surrogate.functions.size());

		ArrayList<FunctionCloneDetectionResultForWeb> result = detector.detectClones(appId, surrogate, threshold, topK,
				avoidSameBinary, progress);

		logger.info("Queried {} functions. Taken {} ms", surrogate.functions.size(),
				System.currentTimeMillis() - start);

		// progress.currentProgress = 1;

		FunctionCloneDataUnit callBack = new FunctionCloneDataUnit(result);
		if (generateCloneGraph) {
			callBack.generateCloneGraph();
			callBack.takenTime = System.currentTimeMillis() - start;
		}
		return callBack;
	}

	public boolean dropBinary(long appId, long binaryId) {
		try {
			objectFactory.dropBinary(appId, binaryId);
			return true;
		} catch (Exception e) {
			logger.error("Failed to delete binary " + binaryId, e);
			return false;
		}

	}

	public void indexBinary(long appId, BinarySurrogate binarySurrogate, LocalJobProgress progress) throws Exception {

		Binary binary = binarySurrogate.toBinary();
		boolean checkExisted = objectFactory.obj_binaries.check(appId, binary.binaryId);

		if (checkExisted) {
			StageInfo stage = progress.nextStage(CloneSearchResources.class,
					"The input binary already existed. Will be merged with existing binary. Same functions will be ignored.");
			stage.complete();
		}
		detector.indexFuncs(appId, binary, progress);
	}

	public void indexBinary(long appId, List<BinaryMultiParts> binaryParts, LocalJobProgress progress)
			throws Exception {
		detector.detector.index(appId, binaryParts, progress);
	}

	public CloneSearchResources(AsmObjectFactory objectFactory, FunctionCloneDetector funcDetector,
			RawFunctionParser parser) throws Exception {
		this.disassemblyFactory = DisassemblyFactory.getDefaultDisassemblyFactory();
		this.objectFactory = objectFactory;
		this.detector = new FunctionCloneDetectorForWeb(funcDetector);
		this.parser = parser;
	}

	public BinarySurrogate disassemble(File file, String newName, LocalJobProgress progress) throws Exception {
		StageInfo stage = progress.nextStage(this.getClass(),
				"Disassemblying using [ " + this.disassemblyFactory.getClass().getSimpleName() + " ]");
		stage.progress = 0.5;
		BinarySurrogate surrogate = this.disassemblyFactory.load(file.getAbsolutePath(), newName);
		stage.complete();
		return surrogate;
	}

	public BinarySurrogateMultipart disassembleIntoMultiPart(File file, String newName, LocalJobProgress progress)
			throws Exception {

		StageInfo stage = progress.nextStage(this.getClass(),
				"Disassemblying into multi-parts using [ " + this.disassemblyFactory.getClass().getSimpleName() + " ]");
		try {
			stage.progress = 0.5;
			BinarySurrogateMultipart surrogates = this.disassemblyFactory.loadAsMultiPart(file.getAbsolutePath(),
					newName);
			stage.complete();
			return surrogates;
		} catch (Exception e) {
			stage.msg = e.toString() + ExceptionUtils.getStackTrace(e);
			throw e;
		}
	}

}
