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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.binclone;

import gnu.trove.map.hash.THashMap;
import gnu.trove.map.hash.TLongObjectHashMap;
import gnu.trove.set.hash.TIntHashSet;
import gnu.trove.set.hash.TLongHashSet;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.SystemInfo;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.array.DmasArrayOperations;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting.NormalizationLevel;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.ram.ObjectFactoryRAM;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.utils.PreNormalizedFunc;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureConstructor;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FreqFeatures;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

public class DetectorBinClone extends FunctionCloneDetector {

	public static FunctionCloneDetector getDetectorBinCloneRam(ArchitectureType type) {
		NormalizationSetting norm_setting = NormalizationSetting.New();
		norm_setting.normalizationLevel = NormalizationLevel.NORM_TYPE;
		norm_setting.normalizeOperation = false;
		AsmProcessor processor = new AsmProcessor(type.retrieveDefinition(), norm_setting);
		return new DetectorBinClone(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "binclone", "binclone"),
				processor);
	}

	public DetectorBinClone(AsmObjectFactory factory, AsmProcessor processor) {
		super(factory);
		this.processor = processor;
		feature = new FeatureConstructor(processor.normalizer, FreqFeatures.getFeatureMemFreq(),
				FreqFeatures.getFeatureOprFreq(), FreqFeatures.getFeatureMemOprFreq());
		median = new double[feature.dimensionality];
	}

	THashMap<String, TLongHashSet> index = new THashMap<>();
	AsmProcessor processor;
	FeatureConstructor feature;
	TLongObjectHashMap<SparseVector> vectorMap;
	TLongObjectHashMap<Function> funcMap;
	TIntHashSet allZeroIndexs;
	double[] median;

	@Override
	protected void indexFuncsToBeImplByChildren(long rid, List<Binary> binary, LocalJobProgress progress)
			throws Exception {

		List<Function> funcs = binary.stream().flatMap(bin -> bin.functions.stream()).collect(Collectors.toList());
		vectorMap = new TLongObjectHashMap<>();
		funcMap = new TLongObjectHashMap<>();
		StageInfo stage = progress.nextStage(this.getClass(), "Constructing feature vectors...");
		funcs.forEach(f -> {
			PreNormalizedFunc pn = new PreNormalizedFunc(f, this.processor.normalizer);
			SparseVector score = feature.scoreNormalizedFragment(pn.subRegions(pn.lines.size(), 1).get(0));
			vectorMap.put(f.functionId, score);
			funcMap.put(f.functionId, f);
		});
		stage.complete();

		stage = progress.nextStage(this.getClass(), "Constructing median vector...");
		allZeroIndexs = new TIntHashSet();
		for (int i = 0; i < feature.dimensionality; ++i) {
			double[] dimI = new double[vectorMap.size()];
			int j = 0;
			for (SparseVector v : vectorMap.valueCollection()) {
				dimI[j++] = v.get(i); // v[i];
			}
			Arrays.sort(dimI);
			median[i] = median(dimI);
			if (DmasArrayOperations.allZero(dimI)) {
				// System.out.println(
				// i + " " + feature.getFeature(i) + " " +
				// feature.getFeatureIndex(feature.getFeature(i)));
				allZeroIndexs.add(i);
			}
		}
		stage.complete();

		stage = progress.nextStage(this.getClass(), "Re-calculating feature vectors...");
		vectorMap.forEachEntry((id, vector) -> {
			for (int i : vector.indexs()) {
				if (vector.get(i) >= median[i]) {
					vector.set(i, 1);// vector[i] = 1;
				} else {
					vector.set(i, 0);// vector[i] = 0;
				}
			}
			return true;
		});
		stage.complete();

		final StageInfo stageIndex = progress.nextStage(this.getClass(), "Indexing... {} features skipped",
				allZeroIndexs.size());
		Counter pcount = new Counter(), gate = new Counter();
		vectorMap.forEachEntry((id, vector) -> {
			pcount.inc();
			if (pcount.getVal() * 100 / vectorMap.size() >= gate.getVal()) {
				SystemInfo info = new SystemInfo();
				stageIndex.updateMsg("{}/{} completed {}% mem tp {} / jvm {} / used {}", pcount.getVal(),
						vectorMap.size(), gate.getVal(), StringResources.FORMAT_2R2D.format(info.memory[0] / 1024),
						StringResources.FORMAT_2R2D.format(info.memory[1] / 1024),
						StringResources.FORMAT_2R2D.format(info.memory[2] / 1024));
				gate.inc();
			}

			for (int i = 0; i < vector.dim; ++i) {
				if (allZeroIndexs.contains(i))
					continue;
				for (int j = i + 1; j < vector.dim; ++j) {
					if (allZeroIndexs.contains(j))
						continue;
					String key = "" + i + j + (int) vector.get(i) + (int) vector.get(j);
					TLongHashSet fids = index.get(key);
					if (fids == null) {
						fids = new TLongHashSet();
						index.put(key, fids);
					}
					fids.add(id);
				}
			}
			return true;
		});
		stageIndex.complete();

	}

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function func,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception {

		final int realDim = feature.dimensionality - allZeroIndexs.size();
		final int ck2 = realDim * (realDim - 1) / 2;

		long id = func.functionId;
		SparseVector vector = vectorMap.get(id);

		HashMap<Long, Integer> counter = new HashMap<>();
		for (int i = 0; i < vector.dim; ++i) {
			if (allZeroIndexs.contains(i))
				continue;
			for (int j = i + 1; j < vector.dim; ++j) {
				if (allZeroIndexs.contains(j))
					continue;
				String key = "" + i + j + (int) vector.get(i) + (int) vector.get(j);
				TLongHashSet fids = index.get(key);
				if (fids != null) {
					fids.forEach(fid -> {
						Integer count = counter.get(fid);
						if (count == null)
							count = 0;
						count += 1;
						counter.put(fid, count);
						return true;
					});
				}
			}
		}

		return counter.entrySet()//
				.stream().map(ent -> new FunctionCloneEntry(funcMap.get(ent.getKey()), ent.getValue() * 1.0 / ck2))//
				.filter(fce -> !avoidSameBinary || (fce.binaryId != func.binaryId))//
				.collect(Collectors.toList());
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("mode", "binclone", "normalizationLevel",
				processor.normalizer.setting);
	}

	public static double median(double[] m) {
		int middle = m.length / 2;
		if (m.length % 2 == 1) {
			return m[middle];
		} else {
			return (m[middle - 1] + m[middle]) / 2.0;
		}
	}

	@Override
	public void init() throws Exception {

	}

	@Override
	public void close() throws Exception {

	}

}
