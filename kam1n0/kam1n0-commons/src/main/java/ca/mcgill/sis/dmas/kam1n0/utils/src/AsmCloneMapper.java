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
package ca.mcgill.sis.dmas.kam1n0.utils.src;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.DmasCollectionOperations;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.EntryTriplet;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizationResource;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting.NormalizationLevel;
import ca.mcgill.sis.dmas.kam1n0.utils.src.ccfinder.SrcCloneDetectorCppCCfinder;

public abstract class AsmCloneMapper {

	private static Logger logger = LoggerFactory.getLogger(AsmCloneMapper.class);

	public static enum Strategy {
		mapByAsmName, mapBySrcName, mapBySrcNameCnt, mapBySrcClone, none;

		public static List<String> getStrVals() {
			return Arrays.asList(Strategy.values()).stream().map(enm -> enm.toString()).collect(Collectors.toList());
		}

		public AsmCloneMapper getInstance() {
			logger.info("Mapping clones by {}", this);
			switch (this) {
			case mapByAsmName:
				return new MapByAsmName();
			case mapBySrcName:
				return new MapBySrcName(false);
			case mapBySrcNameCnt:
				return new MapBySrcName(true);
			case mapBySrcClone:
				return new MapBySrcClone();
			case none:
				return new MapByNone();
			default:
				logger.error("{} type of clone mapping strategy non-existed. using {} as default.", this,
						mapBySrcClone);
				return new MapBySrcClone();
			}
		}

	}

	public ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMap(List<SrcFunction> srcFunctions,
			List<BinarySurrogate> assemblyFunctions) {
		logger.info("Mapping clone using class {} ..", this.getClass().getName());
		return generateAsmCloneMapImplByChild(srcFunctions, assemblyFunctions);
	}

	protected abstract ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMapImplByChild(
			List<SrcFunction> srcFunctions, List<BinarySurrogate> assemblyFunctions);

	public static class MapBySrcName extends AsmCloneMapper {

		private boolean content_clone;
		private AsmLineNormalizer normalizer;

		public MapBySrcName(boolean content_clone) {
			this.content_clone = content_clone;
		}

		@Override
		public ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMapImplByChild(
				List<SrcFunction> srcFunctions, List<BinarySurrogate> binaries) {
			HashMultimap<String, Long> srcNameIdMap = HashMultimap.create();

			binaries.stream().flatMap(bin -> bin.functions.stream())
					.filter(func -> func.srcName != StringResources.STR_EMPTY && !func.srcName.startsWith("sub_"))
					.forEach(func -> {
						srcNameIdMap.put(//
								func.srcName, //
								func.id);
					});
			int src_cnt = (int) srcNameIdMap.keySet().stream().filter(key -> srcNameIdMap.get(key).size() > 1).count();
			if (content_clone) {
				NormalizationSetting setting = new NormalizationSetting();
				setting.normalizationLevel = NormalizationLevel.NORM_TYPE_LENGTH;
				setting.normalizeConstant = true;
				setting.normalizeOperation = false;
				binaries.stream().forEach(bin -> {
					ArchitectureRepresentation def = bin.architecture.type.retrieveDefinition();
					AsmLineNormalizer normalizer = new AsmLineNormalizer(setting,
							new AsmLineNormalizationResource(def));
					bin.functions.stream().forEach(func -> {
						String cnt = StringResources.JOINER_TOKEN.join(//
								normalizer.tokenizeAsmLines(//
										Iterables.concat(func)));
						srcNameIdMap.put(cnt, func.id);
					});
				});
			}
			int asm_cnt = (int) srcNameIdMap.keySet().stream().filter(key -> srcNameIdMap.get(key).size() > 1).count()
					- src_cnt;
			logger.info(
					"---> {} keyed-clones contributed by src name. {} keyed-clonse contributed by asm content (exactly the same)",
					src_cnt, asm_cnt);

			return srcNameIdMap.keySet()//
					.stream()//
					.map(key -> srcNameIdMap.get(key))//
					.filter(val -> val.size() >= 2)
					.flatMap(val -> DmasCollectionOperations.combination(val, 2).stream()).flatMap(cmb -> Arrays.asList(//
							new EntryTriplet<>(cmb.get(0), cmb.get(1), 1.0),
							new EntryTriplet<>(cmb.get(1), cmb.get(0), 1.0)).stream())
					.collect(Collectors.toCollection(ArrayList::new));
		}

		public ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMapImplByChild_OLD(
				List<SrcFunction> srcFunctions, List<FunctionSurrogate> assemblyFunctions, SrcCloneDetector detector) {
			HashMultimap<String, Long> srcFuncNameIdMap = HashMultimap.create();
			Set<Long> vids = assemblyFunctions.stream().map(func -> func.id).collect(Collectors.toSet());

			// only interested in non-empty source founction
			srcFunctions.stream().filter(srcFunc -> srcFunc.asmFuncID != -1 && vids.contains(srcFunc.asmFuncID))
					// removed since sometimes the source code is generated and
					// is gone after cleaning.
					// .filter(srcFunc ->
					// StringResources.JOINER_LINE.join(srcFunc.content).trim().length()
					// > 0)
					.forEach(srcFunc -> {
						int ind = srcFunc.functionName.lastIndexOf(".part.");
						String name;
						if (ind < 0)
							name = srcFunc.functionName;
						else
							name = srcFunc.functionName.substring(0, ind);
						srcFuncNameIdMap.put(//
								name, //
								srcFunc.asmFuncID);
					}); //

			return srcFuncNameIdMap.keySet()//
					.stream()//
					.map(key -> srcFuncNameIdMap.get(key))//
					.filter(val -> val.size() >= 2)
					.flatMap(val -> DmasCollectionOperations.combination(val, 2).stream()).flatMap(cmb -> Arrays.asList(//
							new EntryTriplet<>(cmb.get(0), cmb.get(1), 1.0),
							new EntryTriplet<>(cmb.get(1), cmb.get(0), 1.0)).stream())
					.collect(Collectors.toCollection(ArrayList::new));
		}

	}

	public static class MapByAsmName extends AsmCloneMapper {

		@Override
		public ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMapImplByChild(
				List<SrcFunction> srcFunctions, List<BinarySurrogate> binaries) {
			HashMultimap<String, Long> asmFuncNameIdMap = HashMultimap.create();

			Iterable<FunctionSurrogate> assemblyFunctions = binaries.stream().flatMap(bin -> bin.functions.stream())
					.collect(Collectors.toList());
			assemblyFunctions.forEach(func -> asmFuncNameIdMap.put(func.name, func.id));
			int src_cnt = (int) asmFuncNameIdMap.keySet().stream().filter(key -> asmFuncNameIdMap.get(key).size() > 1)
					.count();
			assemblyFunctions.forEach(func -> {
				String cnt = StringResources.JOINER_TOKEN
						.join(func.blocks.stream().flatMap(blk -> blk.asmLines().stream()).filter(in -> in.size() > 1)
								.map(in -> in.subList(1, in.size())).collect(Collectors.toList()));
				asmFuncNameIdMap.put(cnt, func.id);
			});
			int asm_cnt = (int) asmFuncNameIdMap.keySet().stream().filter(key -> asmFuncNameIdMap.get(key).size() > 1)
					.count() - src_cnt;
			logger.info(
					"---> {} keyed-clones contributed by src name. {} keyed-clonse contributed by asm content (exactly the same)",
					src_cnt, asm_cnt);

			// 2 combination of the asm functions that have the same name.
			return asmFuncNameIdMap.keySet()//
					.stream()//
					.map(key -> asmFuncNameIdMap.get(key))//
					.filter(val -> val.size() >= 2)
					.flatMap(val -> DmasCollectionOperations.combination(val, 2).stream()).flatMap(cmb -> Arrays.asList(//
							new EntryTriplet<>(cmb.get(0), cmb.get(1), 1.0),
							new EntryTriplet<>(cmb.get(1), cmb.get(0), 1.0)).stream())
					.collect(Collectors.toCollection(ArrayList::new));
		}

	}

	public static class MapBySrcClone extends AsmCloneMapper {

		@Override
		public ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMapImplByChild(
				List<SrcFunction> srcFunctions, List<BinarySurrogate> binaries) {

			SrcCloneDetector detector = new SrcCloneDetectorCppCCfinder();

			Iterable<FunctionSurrogate> assemblyFunctions = binaries.stream().flatMap(bin -> bin.functions.stream())
					.collect(Collectors.toList());
			srcFunctions = srcFunctions.stream().filter(srcf -> srcf.content.size() > 0).collect(Collectors.toList());

			if (detector.isValid()) {
				logger.info("Processing {} source functions", srcFunctions.size());
				try {
					detector.detectClones(srcFunctions, srcFunctions);
				} catch (Exception e) {
					logger.error("Failed to detect clone using " + this.getClass().getName(), e);
					return new ArrayList<>();
				}
			} else {
				logger.error("the selected detector {} is not configured/valid... ", this.getClass().getName());
				return new ArrayList<>();
			}

			HashMap<String, Double> result = new HashMap<>();

			HashMultimap<Long, Long> srcid_asmid_map = HashMultimap.create();
			HashMap<Long, SrcFunction> srcid_srcfunc_map = new HashMap<>();
			assemblyFunctions.forEach(func -> srcid_asmid_map.put(func.srcid, func.id));
			srcFunctions.forEach(func -> srcid_srcfunc_map.put(func.id, func));

			srcid_srcfunc_map.values().forEach(srcFunc -> {
				Set<Long> srcFuncAsmIds = srcid_asmid_map.get(srcFunc.id);
				if (srcFuncAsmIds == null || srcFuncAsmIds.size() < 1)
					return;
				srcFunc.clones.forEach(clone -> {
					HashSet<Long> allAsmIdsAssociatedToThisClone = new HashSet<>(srcFuncAsmIds);
					SrcFunction tarSrcFunc = srcid_srcfunc_map.get(clone.key);
					if (tarSrcFunc != null) {
						Set<Long> tarSrcFuncAsmIds = srcid_asmid_map.get(tarSrcFunc.id);
						if (tarSrcFuncAsmIds != null && srcFuncAsmIds.size() > 0) {
							allAsmIdsAssociatedToThisClone.addAll(tarSrcFuncAsmIds);
							if (allAsmIdsAssociatedToThisClone.size() > 1) {
								(DmasCollectionOperations.combination(allAsmIdsAssociatedToThisClone, 2))
										.forEach(cmb -> {
											{
												String clone_pair;
												clone_pair = StringResources.JOINER_TOKEN.join(cmb.get(0), cmb.get(1));
												// Double weight =
												// result.get(clone_pair);
												// if (weight == null)
												result.put(clone_pair, clone.value);
											}

											{
												String clone_pair;
												clone_pair = StringResources.JOINER_TOKEN.join(cmb.get(1), cmb.get(0));
												// Double weight =
												// result.get(clone_pair);
												// if (weight == null)
												result.put(clone_pair, clone.value);
											}
											// else if (!weight.equals(clone.value)) {
											// logger.error(
											// "Find bi-directed link (src code): src
											// {}, des {}, weight {} & {}; but has
											// different weights ",
											// srcFunc.id, clone.key, clone.value,
											// weight);
											// }
										});
							}
						}
					}
				});
			});

			ArrayList<EntryTriplet<Long, Long, Double>> returnList = new ArrayList<>();
			for (Entry<String, Double> entry : result.entrySet()) {
				String[] pids = entry.getKey().split(StringResources.STR_TOKENBREAK);
				returnList.add(new EntryTriplet<Long, Long, Double>(Long.parseLong(pids[0]), Long.parseLong(pids[1]),
						entry.getValue()));
			}

			return returnList;
		}

	}

	public static class MapByNone extends AsmCloneMapper {

		@Override
		protected ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMapImplByChild(
				List<SrcFunction> srcFunctions, List<BinarySurrogate> assemblyFunctions) {
			return new ArrayList<>();
		}

	}

	@Deprecated
	public static ArrayList<EntryTriplet<Long, Long, Double>> generateAsmCloneMapForInjection(
			List<SrcFunction> srcFunctions, List<FunctionSurrogate> assemblyFunctions) {

		HashMap<String, Double> result = new HashMap<>();

		HashMap<String, SrcFunction> srcFunctionInjectionIDMap = new HashMap<>();
		for (SrcFunction srcFunction : srcFunctions) {
			srcFunctionInjectionIDMap.put(srcFunction.injectedID.toLowerCase(), srcFunction);
		}

		for (FunctionSurrogate asmFunction : assemblyFunctions) {
			long srcid = asmFunction.srcid;
			String srcid_hex = Integer.toHexString(Long.hashCode(srcid));
			if (srcid == -1 || !srcFunctionInjectionIDMap.containsKey(srcid_hex))
				continue;
			SrcFunction srcFunction = srcFunctionInjectionIDMap.get(srcid_hex);
			if (srcFunction.clones.size() > 0) {
				for (EntryPair<Long, Double> entry : srcFunction.clones) {
					if (entry.key.equals(srcFunction.id))
						continue;
					String clone_src_id_hex = Integer.toHexString(Long.hashCode(entry.key));
					SrcFunction clone_src_function = srcFunctionInjectionIDMap.get(clone_src_id_hex);
					if (clone_src_function == null) {
						logger.error(
								"Unexpected logic error: the src function with id {} is not in the list of src functions in input.",
								srcid);
						continue;
					}
					long asmID = clone_src_function.asmFuncID == -1 ? clone_src_function.asmBlockID
							: clone_src_function.asmFuncID;
					if (asmID == -1)
						continue;
					String clone_pair;
					if (asmFunction.id < asmID) {
						clone_pair = StringResources.JOINER_TOKEN.join(asmFunction.id, asmID);
					} else {
						clone_pair = StringResources.JOINER_TOKEN.join(asmID, asmFunction.id);
					}
					Double weight = result.get(clone_pair);
					if (weight == null)
						result.put(clone_pair, entry.value);
					else if (!weight.equals(entry.value)) {
						logger.error("Find directed link (src code): src {}, des {}, weight {} & {}", srcFunction.id,
								entry.key, entry.value, weight);
					}
				}
			}
		}
		ArrayList<EntryTriplet<Long, Long, Double>> returnList = new ArrayList<>();
		for (Entry<String, Double> entry : result.entrySet()) {
			String[] pids = entry.getKey().split(StringResources.STR_TOKENBREAK);
			returnList.add(new EntryTriplet<Long, Long, Double>(Long.parseLong(pids[0]), Long.parseLong(pids[1]),
					entry.getValue()));
		}

		return returnList;
	}

}
