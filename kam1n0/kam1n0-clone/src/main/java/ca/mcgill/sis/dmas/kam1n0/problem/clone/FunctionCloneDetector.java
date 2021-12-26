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
package ca.mcgill.sis.dmas.kam1n0.problem.clone;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.LoggerFactory;

import com.google.common.collect.Iterables;

import org.slf4j.Logger;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogateMultipart;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.BinaryMultiParts;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public abstract class FunctionCloneDetector {

	private static Logger logger = LoggerFactory.getLogger(FunctionCloneDetector.class);

	protected transient AsmObjectFactory factory;

	public FunctionCloneDetector(AsmObjectFactory factory) {
		this.factory = factory;
	}

	public FunctionCloneDetector() {
		this.factory = null;
	}

	protected abstract List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception;

	protected abstract void indexFuncsToBeImplByChildren(long rid, List<Binary> binaries, LocalJobProgress progress)
			throws Exception;

	/**
	 * Default implementation of batch indexing (well, we index it one by one so
	 * don't have to keep them in memory. This method can be override. If it is
	 * override, you have to add the object to AsmFactory by yourself.
	 * 
	 * @param rid
	 * @param binaries
	 *            Binary representations. Each binary contains iterable subparts.
	 * @param progress
	 *            Reporting progress.
	 * @throws Exception
	 */
	public void index(long rid, Iterable<? extends BinaryMultiParts> binaries, LocalJobProgress progress)
			throws Exception {
		int total = Iterables.size(binaries);
		int binIndx = 1;
		StageInfo stage_binary = progress.nextStage(this.getClass());
		for (BinaryMultiParts parts : binaries) {
			stage_binary.updateMsg("Indexing [ {} / {} ] binary files.", binIndx, total);
			stage_binary.progress = (binIndx - 1) * 1.0 / total;
			StageInfo stage_part = progress.nextStage(this.getClass());
			stage_part.progress = 0.5;
			int partIndx = 1;
			for (Binary part : parts) {
				stage_part.updateMsg("Indexing part {}/{} for {}", partIndx, parts.getSize(), part.binaryName);
				stage_part.progress = partIndx * 1.0 / parts.getSize();
				StageInfo stage_store = progress.nextStage(this.getClass(),
						"Storing {} functions into database for {} part {}.", part.functions.size(), part.binaryName,
						partIndx);
				if (this.factory != null)
					this.factory.addBinary(rid, part, stage_store);
				stage_store.complete();
				this.indexFuncsToBeImplByChildren(rid, Arrays.asList(part), progress);

				partIndx++;
			}
			binIndx++;
			stage_part.complete();
		}
		stage_binary.complete();
	}

	public final void index(long rid, List<Binary> binaries, LocalJobProgress progress) throws Exception {
		List<BinaryMultiParts> mulitParts = binaries.stream().map(binary -> binary.converToMultiPart())
				.collect(Collectors.toList());
		this.index(rid, mulitParts, progress);
	}

	public final void index(long rid, LocalJobProgress progress, Binary... binaries) throws Exception {
		List<BinaryMultiParts> mulitParts = Arrays.stream(binaries).map(binary -> binary.converToMultiPart())
				.collect(Collectors.toList());
		this.index(rid, mulitParts, progress);
	}

	/**
	 * Note: may return more than topK results depending on clone detector implementation and if there are ties for the
	 * 'topK'th position (similarity-wise).
	 */
	public final List<FunctionCloneEntry> detectClonesForFunc(long rid, Function function, double threadshold, int topK,
			boolean avoidSameBinary) throws Exception {
		return this.detectClonesForFuncToBeImpleByChildren(rid, function, threadshold, topK, avoidSameBinary);
	}

	public abstract String params();

	public abstract void init() throws Exception;

	public abstract void close() throws Exception;

	public void clean(long appId) throws Exception {
		return;
	}

	public boolean dump(String path) {
		logger.warn(
				"Receiving command to dump the index of this detector; but the underlying detector implementation does not implement such functionality.");
		return false;
	}

	public void clear(long rid) {

	}

}
