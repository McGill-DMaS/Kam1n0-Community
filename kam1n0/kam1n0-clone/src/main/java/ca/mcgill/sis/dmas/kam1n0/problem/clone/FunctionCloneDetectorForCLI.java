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

import gnu.trove.set.hash.TLongHashSet;
import scala.Tuple2;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;

public class FunctionCloneDetectorForCLI {

	private static Logger logger = LoggerFactory.getLogger(FunctionCloneDetectorForCLI.class);

	public FunctionCloneDetector detector = null;

	public double lastIndexTime;
	private TLongHashSet searchSpace = new TLongHashSet();
	private String caseName;

	public FunctionCloneDetectorForCLI(FunctionCloneDetector detector) {
		this.detector = detector;
	}

	public void index(long rid, List<BinarySurrogate> toBeIndexed) {
		LocalJobProgress indexProgress = new LocalJobProgress();
		Tuple2<TLongHashSet, List<Binary>> tp_index = this.preprocess(toBeIndexed);
		this.searchSpace.addAll(tp_index._1);
		lastIndexTime = 0;
		try {
			long now = System.nanoTime();
			logger.info("indexing {} funcs ...", searchSpace.size());
			detector.index(rid, tp_index._2, indexProgress);
			lastIndexTime = (System.nanoTime() - now) * 1.0 / 1000000;
		} catch (Exception e) {
			logger.error("Failed to index binaries; returning null;", e);
		}
	}

	public FunctionCloneDetectionResultForCLI detectClone(long rid, List<BinarySurrogate> binsToSearch,
			double threshold, int topK) {
		return detectClone(rid, binsToSearch, threshold, topK, false);
	}

	/**
	 * For compatability. Introduced an additional param avoidSameBinary into
	 * signature.
	 * 
	 * @param rid
	 * @param binsToSearch
	 * @param threshold
	 * @param topK
	 * @param progress
	 * @return
	 */
	public FunctionCloneDetectionResultForCLI detectClone(long rid, List<BinarySurrogate> binsToSearch,
			double threshold, int topK, boolean progress) {
		return detectClone(rid, binsToSearch, threshold, topK, true, progress);
	}

	public FunctionCloneDetectionResultForCLI detectClone(long rid, List<BinarySurrogate> binsToSearch,
			double threshold, int topK, boolean avoidSameBinary, boolean progress) {
		ConcurrentHashMap<EntryPair<Long, Long>, Double> tmpSet = new ConcurrentHashMap<>();
		Tuple2<TLongHashSet, List<Binary>> tp_search = this.preprocess(binsToSearch);
		TLongHashSet querySpace = tp_search._1;
		List<Binary> queries = tp_search._2;

		// detect clones
		// also de-duplicate the detection results:
		Counter counter = Counter.zero();
		Counter gate = Counter.zero();
		int total = querySpace.size();
		long now = System.nanoTime();
		logger.info("Searching clones for {} funcs from {}...", total, new File(binsToSearch.get(0).name).getName());
		ForkJoinPool pool = new ForkJoinPool(45);
		try {
			pool.submit(() -> {
				queries.stream().flatMap(bin -> bin.functions.stream()).collect(Collectors.toList()).parallelStream()
						.forEach(function -> {
							// report:
							counter.inc();
							if (progress && counter.getVal() * 100.0 / total > gate.getVal()) {
								gate.inc();
								logger.info("Progress: {} %",
										StringResources.FORMAT_2R4D.format(counter.getVal() * 100.0 / total));
							}

							try {
								detector.detectClonesForFunc(rid, function, threshold, topK, avoidSameBinary)
										//
										.stream()
										//
										.filter(entry -> entry.similarity >= threshold)
										//
										.filter(entry -> entry.functionId != function.functionId)
										//
										.map(entry -> {
											Long v1 = function.functionId;
											Long v2 = entry.functionId;
											// if (v1 < v2)
											// return new EntryPair<>(new
											// EntryPair<>(v1, v2),
											// entry.similarity);
											// else
											return new EntryPair<>(new EntryPair<>(v1, v2), entry.similarity);
										}).forEach(clonePair -> tmpSet.compute(clonePair.key, //
												(k, v) -> v == null ? //
								(clonePair.value) // clonePair
														: //
								(clonePair.value > v ? clonePair.value : v)));
							} catch (Exception e) {
								logger.error("Failed to detect clone for a function.", e);
							}
						});
				return 0;
			}).get();
		} catch (Exception e) {
			logger.error("Failed to execute searching command in a designated pool.", e);
		}

		double timeSearch = (System.nanoTime() - now) * 1.0 / 1000000;

		ArrayList<EntryTriplet<Long, Long, Double>> restl = tmpSet.entrySet().stream()
				.map(ent -> new EntryTriplet<>(ent.getKey().key, ent.getKey().value, ent.getValue()))
				.collect(Collectors.toCollection(ArrayList::new));

		FunctionCloneDetectionResultForCLI rescli = new FunctionCloneDetectionResultForCLI(restl, searchSpace,
				querySpace, caseName, caseName);
		rescli.timeIndex = lastIndexTime;
		rescli.timeSearch = timeSearch;

		return rescli;
	}

	private String getNames(Iterable<BinarySurrogate> binaries) {
		ArrayList<String> names = new ArrayList<>();
		binaries.forEach(binary -> {
			names.add(binary.name);
		});
		return StringResources.longestCommonNmae(names);
	}

	private Tuple2<TLongHashSet, List<Binary>> preprocess(List<BinarySurrogate> binaries) {
		TLongHashSet space = new TLongHashSet();
		ArrayList<Binary> bins = new ArrayList<>();
		binaries.forEach(binary -> {
			Binary nBinary = binary.toBinary();
			bins.add(nBinary);
			space.addAll(nBinary.functionIds);
		});
		return new Tuple2<TLongHashSet, List<Binary>>(space, bins);
	}

	public FunctionCloneDetectionResultForCLI indexAndDetect(long rid, ArrayList<BinarySurrogate> binaries,
			double threshold) throws Exception {
		return indexAndDetect(rid, binaries, threshold, Integer.MAX_VALUE);
	}

	public FunctionCloneDetectionResultForCLI indexAndDetect(long rid, List<BinarySurrogate> binaries, double threshold,
			int topK) throws Exception {
		this.caseName = this.getNames(binaries);
		this.index(rid, binaries);
		return this.detectClone(rid, binaries, threshold, topK);

	}

	public FunctionCloneDetectionResultForCLI indexAndDetect(long rid, List<BinarySurrogate> toBeIndexes,
			List<BinarySurrogate> toBeSearched, double threshold, int topK) throws Exception {
		return this.indexAndDetect(rid, toBeIndexes, toBeSearched, threshold, topK, false);
	}

	public FunctionCloneDetectionResultForCLI indexAndDetect(long rid, List<BinarySurrogate> toBeIndexes,
			List<BinarySurrogate> toBeSearched, double threshold, int topK, boolean progress) throws Exception {
		this.index(rid, toBeIndexes);
		return this.detectClone(rid, toBeSearched, threshold, topK, progress);
	}

	public String params() {
		return detector.params();
	}

	public void init() throws Exception {
		detector.init();
	}

	public void close() throws Exception {
		detector.close();
	}

}
