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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IntSummaryStatistics;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Sets;
import com.microsoft.z3.Model;
import com.microsoft.z3.Params;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Status;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.env.SystemInfo;
import ca.mcgill.sis.dmas.env.LocalJobProgress.StageInfo;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.io.collection.IteratorSafeGen;
import ca.mcgill.sis.dmas.io.collection.Pool;
import ca.mcgill.sis.dmas.io.collection.heap.Ranker;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.graph.BlockLogicWrapper;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.ScoringUnit.F_ScoringUnit;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocksImpl3;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.Indexer;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocks.HashedLinkedBlock;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph.NodeType;
import ca.mcgill.sis.dmas.kam1n0.symbolic.SimNode;
import ca.mcgill.sis.dmas.kam1n0.symbolic.Symbol;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.LaplaceBox;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.RunConfigurable;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.RunConfiguration;
import ca.mcgill.sis.dmas.kam1n0.symbolic.run.RunResult;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import scala.Tuple2;
import scala.Tuple3;

public class DifferentialSymbolicIndexer extends Indexer<Block> implements Serializable {

	private static final long serialVersionUID = 3325447631567533634L;
	private static Logger logger = LoggerFactory.getLogger(DifferentialSymbolicIndexer.class);

	public List<Long> vals = new ArrayList<>();

	public Random random = new Random();
	public final int maxSize;
	public final int maxDepth;
	public Long startValue = 0xaaaaaaal;
	public int bound = 6000;
	public int maxRound = 11;

	public int debugLevel = 2;
	private int pool_core = 10;
	DifferentialIndexAbstract index;
	private ExecutorService threadPoolExecutor;
	private AsmObjectFactory factory;
	private LogicGraphFactory logicFactory;

	private static long rootId = -1;

	public class Detector extends FunctionCloneDetector {

		// public HashMap<Long, Set<String>> ccalls = new HashMap<>();

		public Detector(AsmObjectFactory factory) {
			super(factory);
		}

		@Override
		protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
				double threadshold, int topK, boolean avoidSameBinary) throws Exception {

			// hack: causing unknown error..
			if (function.blocks.size() > 500)
				return new ArrayList<>();

			// transform query (if haven't doen so)
			// updated block will be transfered back to the UI (to include vex
			// code etc.)
			function.blocks = function.blocks.stream().map(LogicGraphFactory::translate).collect(Collectors.toList());

			ArrayList<Block> vBlks = new ArrayList<>();

			HashSet<Tuple2<Long, Long>> links = new HashSet<>();
			Counter finalFuncLength = Counter.zero();
			for (Block blk : function) {
				int blkLength = blk.getAsmLines().size();
				vBlks.add(blk);
				finalFuncLength.inc(blkLength);
			}
			Set<Long> vBlkIds = vBlks.stream().map(blk -> blk.blockId).collect(Collectors.toSet());
			for (Block blk : vBlks) {
				blk.callingBlocks.stream().filter(callee -> vBlkIds.contains(callee))
						.forEach(callee -> links.add(new Tuple2<Long, Long>(blk.blockId, callee)));
				links.add(new Tuple2<>(blk.blockId, blk.blockId));
			}

			ScoringUnit su = querySU(rid, vBlks, links);

			if (debugLevel > 1)
				logger.info("     Collected SU.");

			/**
			 * Debugging section here:
			 */
			if (debugLevel > 1) {

				SystemInfo info = new SystemInfo();
				logger.info("     Sys: {}", info.toString());

				List<F_ScoringUnit> ranks = su.getTopK(topK);
				Counter fc = Counter.zero();
				String bin = null;
				boolean found = false;
				for (int i = 0; i < ranks.size(); i++) {
					Function func = factory.obj_functions.querySingleBaisc(rid, ranks.get(i).srcfid);
					if (func == null) {
						logger.error("Non-existed function: {}::{}", rid, ranks.get(i).srcfid);
						continue;
					}
					if (bin == null)
						bin = (new File(func.binaryName)).getName();
					if (func.functionName.equals(function.functionName)) {
						fc.inc();
						if (i == 0) {
							debugP1Counter.inc();
							found = true;
						}
						if (i < topK)
							debugRecallCounter.inc();
						logger.info("   #{} {}founded. calls {}.", StringResources.FORMAT_2R.format(i),
								i == 0 ? "" : "%%", function.ccalls.stream().map(call -> call.replaceAll("_", ""))
										.collect(Collectors.toSet()));
					} else if (i < 3) {
						logger.info("   #{} {} ", StringResources.FORMAT_2R.format(i), func.functionName);
					}
				}
				debugTotalCounter.inc();
				logger.info(" {} Summary: Total:{} P1:{} R20:{} {}", found ? "*" : "-", debugTotalCounter.getVal(),
						debugP1Counter.getVal(), debugRecallCounter.getVal(), bin);

			}
			/**
			 * Debug section end
			 */
			List<F_ScoringUnit> ranks = su.getTopK(topK);
			return ranks.parallelStream().map(cand -> {
				Function func = factory.obj_functions.querySingle(rid, cand.srcfid);
				if (func == null) {
					logger.error("Function not found {} {}", cand.srcfid,
							cand.map.entrySet().stream().findAny().get().getValue().tar.functionName);
					return null;
				}
				func.fill(rid, factory);
				FunctionCloneEntry entry = new FunctionCloneEntry(func, cand.score);
				Map<Long, HashedLinkedBlock> blkMap = StreamSupport.stream(func.spliterator(), false)
						.collect(Collectors.toMap(blk -> blk.blockId, blk -> new HashedLinkedBlock(blk)));
				List<Tuple3<HashedLinkedBlock, HashedLinkedBlock, Double>> tps = cand.map.values().stream()
						.flatMap(tarc -> tarc.candidates.values().stream()
								.map(srcb -> new Tuple3<>(new HashedLinkedBlock(tarc.tar), blkMap.get(srcb.srcbid),
										srcb.score)))
						.collect(Collectors.toList());
				SubgraphBlocksImpl3.mergeSingles(tps).subgraphs.forEach(graph -> entry.clonedParts.add(graph.stream()
						.map(lk -> new Tuple3<>(lk.src.original.blockId, lk.tar.original.blockId, lk.score))
						.collect(Collectors.toCollection(HashSet::new))));
				return entry;
			}).filter(val -> val != null).filter(val -> !avoidSameBinary || val.binaryId != function.binaryId)
					.collect(Collectors.toList());
		}

		@Override
		protected void indexFuncsToBeImplByChildren(long rid, List<Binary> binaries, LocalJobProgress progress)
				throws Exception {

			List<Block> blks = binaries.stream().flatMap(bin -> bin.functions.stream()).flatMap(func -> {
				return func.blocks.stream();
			}).collect(Collectors.toList());
			DifferentialSymbolicIndexer.this.index(rid, blks, progress);

		}

		@Override
		public String params() {
			return DifferentialSymbolicIndexer.this.params();
		}

		@Override
		public void init() throws Exception {
			DifferentialSymbolicIndexer.this.init();
		}

		@Override
		public void close() throws Exception {

		}

		@Override
		public boolean dump(String path) {
			return DifferentialSymbolicIndexer.this.dump(path);
		}

	}

	public static class BoxReadyThread<T> implements Callable<T> {

		private java.util.function.Function<LaplaceBox, T> func;

		public BoxReadyThread(java.util.function.Function<LaplaceBox, T> func) {
			this.func = func;
		}

		private static final ThreadLocal<LaplaceBox> threadLocal = new ThreadLocal<LaplaceBox>() {
			@Override
			protected LaplaceBox initialValue() {
				logger.info("Creating a local laplace box for a thread.");
				return SymbolicUtils.createBoxForLocalThread();
			}
		};

		@Override
		public T call() throws Exception {
			LaplaceBox box = threadLocal.get();
			return this.func.apply(box);
		}

	}

	public DifferentialSymbolicIndexer(SparkInstance spark, AsmObjectFactory factory, LogicGraphFactory logicFactory,
			int seed, int maxSize, int maxDepth, int bound, int debuglevel, DifferentialIndexAbstract index) {
		super(spark);
		this.factory = factory;
		this.logicFactory = logicFactory;
		this.maxSize = maxSize;
		this.random = new Random(seed);
		this.bound = bound;
		this.maxDepth = maxDepth;
		this.index = index;
		this.debugLevel = debuglevel;
		this.threadPoolExecutor = Executors.newFixedThreadPool(this.pool_core, Executors.defaultThreadFactory());
	}

	public List<Long> extractCnts(Iterable<RunConfiguration> confs) {
		ArrayList<Long> conts = new ArrayList<>();
		for (RunConfiguration conf : confs) {
			for (Symbol cont : conf.outputSymbol.getConstants()) {
				if (cont.cNode.children.size() > 0 && (!cont.cNode.isAddr()))
					for (ComputationNode child : cont.cNode.getChildren(conf.configurable))
						if (child != null) //
							if (child.type == NodeType.condition //
									|| (child.ccall_oprName != null) //
									|| (child.oprType != null && child.oprType.att()._generic_name != null
											&& child.oprType.att()._generic_name.contains("Cmp"))) {
								conts.add(cont.cNode.constant.getVal());
								break;
							}
			}
		}
		return conts;
	}

	public Long determineNewVal(List<Long> conts, Set<Long> history) {

		// we need to ensure that the input is the same for 32bit and 64 bit.
		// in order to match them
		if (conts.size() == 0) {
			return (long) random.nextInt();
		}

		int times = 0;
		long val = 0;
		// LT EQ GT 2'S-COMPLEMENT
		List<Long> bias = Arrays.asList(-1l, 0l, 1l, 0l);
		do {
			val = conts.get(random.nextInt(conts.size()));
			bias.set(bias.size() - 1, (val * -2));
			val = val + bias.get(random.nextInt(bias.size()));
			// FORCE CONVERSION:
			val = (int) val;
			times++;
		} while (history.contains(val) & times < 10);
		history.add(val);

		return val;
	}

	public Long determineMajorityExact(Stream<IOSymHashMeta> entries, Set<Long> history) {
		List<Long> a = entries.flatMap(ent -> ent.input.stream()).collect(Collectors.toList());
		Long previous = a.get(0);
		Long popular = a.get(0);
		int count = 1;
		int maxCount = 1;

		for (int i = 1; i < a.size(); i++) {
			if (a.get(i) == previous)
				count++;
			else {
				if (count > maxCount) {
					popular = a.get(i - 1);
					maxCount = count;
				}
				previous = a.get(i);
				count = 1;
			}
		}
		return count > maxCount ? a.get(random.nextInt(a.size())) : popular;
	}

	public Long determineMajorityRamdon(Stream<IOSymHashMeta> hms, Set<Long> history) {
		List<Long> a = hms.flatMap(ent -> ent.input.stream()).collect(Collectors.toList());
		if (a.size() == 0)
			return startValue;
		long val = 0;
		int times = 0;
		do {
			val = a.get(random.nextInt(a.size()));
			times++;
		} while (history.contains(val) & times < 10);
		history.add(val);
		return val;
	}

	public Long determineNewValSolver(Long newMajority, String oldOutput,
			List<Tuple2<IOSymHashMeta, RunConfiguration>> nlogics, LaplaceBox box) {

		SimNode input = new SimNode(box.ctx, "kamtmp", VexVariableType.Ity_I32);

		List<Tuple2<RunConfiguration, SimNode>> conditions = nlogics.stream().map(ent -> {
			IOSymHashMeta hm = ent._1;
			RunConfiguration conf = ent._2;
			RunConfigurable confb = ent._2.configurable;
			// get the right configuration
			List<Long> oldInputs = hm.input;
			for (int i = 0; i < oldInputs.size(); ++i)
				if (oldInputs.get(i).equals(newMajority)) {

					RunConfiguration newConf = conf.copy();
					newConf.setValue(oldInputs);
					SimNode oldInput = newConf.inputAssignments.get(i).sym.sNode;
					newConf.inputAssignments.remove(i);
					Symbol outputNode = newConf.subtitute();

					SimNode newInput = input;
					if (oldInput.size() > input.size()) {
						newInput = input.zeroExtend(oldInput.size());
					} else if (oldInput.size() < input.size()) {
						newInput = input.extract(oldInput.size() - 1, 0);
					}

					SimNode outputWithNewInputs = outputNode.sNode.subtitute(oldInput, newInput);
					// convert to int.
					outputWithNewInputs = outputWithNewInputs.to(32);

					SimNode cond;
					// whether we still have the same output?
					if (oldOutput.equals(LaplaceBox.IDEN_NEXT)) {
						cond = outputWithNewInputs.cmpeq(confb.nextBlkSeq);
					} else if (oldOutput.equals(LaplaceBox.IDEN_SKIP)) {
						cond = outputWithNewInputs.cmpne(confb.nextBlkSeq);
					} else {
						long oldOutputVal = Long.parseUnsignedLong(oldOutput, 16);
						cond = outputWithNewInputs.cmpeq(oldOutputVal);
					}
					return new Tuple2<>(conf, cond);
				}
			RunConfiguration newConf = conf.copy();
			newConf.setValue(oldInputs);
			SimNode outputWithNewInputs = newConf.subtitute().sNode;
			// convert to int.
			outputWithNewInputs = outputWithNewInputs.to(32);
			SimNode cond;
			// whether we still have the same output?
			if (oldOutput.equals(LaplaceBox.IDEN_NEXT)) {
				cond = outputWithNewInputs.cmpeq(confb.nextBlkSeq);
			} else if (oldOutput.equals(LaplaceBox.IDEN_SKIP)) {
				cond = outputWithNewInputs.cmpne(confb.nextBlkSeq);
			} else {
				long oldOutputVal = Long.parseUnsignedLong(oldOutput, 16);
				cond = outputWithNewInputs.cmpeq(oldOutputVal);
			}
			return new Tuple2<>(newConf, cond);
		}).filter(tp -> tp != null)//
				.collect(Collectors.toList());

		Solver solver = box.getSolver();
		Params timeout = box.ctx.mkParams();
		timeout.add("timeout", 80 * 1000); // 80s
		solver.setParameters(timeout);
		SimNode sum = null;
		// we calculate the sum of all previous condition.
		// condition yields one if it is true.
		// if there is one different the sum value should be (0, |conditions|-1)
		for (Tuple2<RunConfiguration, SimNode> cond : conditions) {
			if (sum == null)
				sum = cond._2;
			else
				sum = sum.add(cond._2);
		}
		SimNode lowerbound = sum.cmpgt(0, false);
		SimNode higherbound = sum.cmplt(conditions.size(), false);
		solver.add(lowerbound.and(higherbound).isTrue());
		if (solver.check().equals(Status.SATISFIABLE)) {
			Model model = solver.getModel();
			long newVal = box.run(model, input);
			if (debugLevel > 3) {
				logger.info("{}/{} split", box.run(model, sum), conditions.size());
				conditions.forEach(tp -> {

					SimNode cond = tp._2;
					RunConfiguration newConf = tp._1;
					SimNode toutput = newConf.subtitute().sNode.setValues(input, newVal);
					long raw = box.run(toutput);
					long extracted = box.run(toutput.to(32));
					logger.info("cond:{} val:{}:{} - hid:{} inputs:{}", box.run(model, cond.setValues(input, newVal)),
							raw, extracted, Integer.toHexString(newConf.outputSymbol.cNode.sHash),
							newConf.inputAssignments);
				});
			}
			return newVal;
		} else
			return null;

	}

	public void splitBucket(long rid, Location loc, LaplaceBox box) {

		if (loc.depth > this.maxDepth) {
			logger.info("Reaching leaf with {} nodes", loc.bk == null ? 0 : loc.bk.count);
			return;
		}

		HashMap<Long, RunConfigurable> logicMap = new HashMap<>();
		IOBucketCtn bucket = index.loadBucket(rid, loc.K1, loc.conf.result.output.value);
		if (debugLevel > 0)
			logger.info("Loading {} hMetas for spliting bucket.", bucket.entries.size());

		bucket.entries.stream().parallel().filter(hm -> hm != null).map(hm -> hm.rep).distinct()
				.map(rep -> new Tuple2<>(rep, logicFactory.getLogicGraph(rid, rep))).filter(tp -> tp._2 != null)
				.collect(Collectors.toList()).forEach(tp -> {
					if (!logicMap.containsKey(tp._1)) {
						logicMap.put(tp._1, tp._2.toConfigurable(box));
					}
				});

		if (debugLevel > 0)
			logger.info("Spliting {} bbs of ##### loc {}::{}", bucket.entries.size(), loc.K1,
					loc.conf.result.output.value);
		// use cached IO result
		this.splitBucket(rid, loc.K1, loc.conf.result.output.value, bucket, box, logicMap, loc.depth);
	}

	private void splitBucket(long rid, Long K1, String K2, IOBucketCtn bucket, LaplaceBox box,
			HashMap<Long, RunConfigurable> logicMap, int depth) {

		if (depth > this.maxDepth) {
			logger.info("Reaching leaf with {} nodes", bucket.entries.size());
			return;
		}

		List<Tuple2<IOSymHashMeta, RunConfiguration>> logics = bucket.entries.stream().map(hm -> {
			RunConfigurable configurable = logicMap.get(hm.rep);
			if (configurable == null)
				return null;
			RunConfiguration conf = configurable.getConfiguration(hm.varName);
			if (conf != null)
				return new Tuple2<>(hm, conf);
			return null;
		}).filter(ent -> ent != null).collect(Collectors.toList());
		int sizeToBeSplit = logics.size();

		String space = "";
		if (debugLevel > 0)
			for (int i = 0; i < depth; ++i)
				space += " ";
		String prefix = space;

		if (debugLevel > 1)
			logger.info(prefix + "Depth {} val {} of size {}", depth, K2, sizeToBeSplit);
		// if (debugLevel > 2) {
		// logger.info("Before split...");
		// logics.forEach(ent -> {
		// RunConfiguration conf = ent._2;
		// logger.info(prefix + "Depth {} - {}: H:{} I:{} S:{} F:{} A:{}",
		// depth, conf.outputSymbol.cNode.varName,
		// Integer.toHexString(conf.outputSymbol.cNode.sHash),
		// conf.inputAssignments,
		// conf.outputSymbol.cNode.sExpression(conf.configurable.nodes),
		// conf.configurable.funcName,
		// conf.configurable.arch.type);
		// });
		// }

		bucket.count = 0;
		bucket.K1 = UUID.randomUUID().getLeastSignificantBits();

		HashMap<String, IOBucketCtn> splitBuckets = new HashMap<>();
		int round = 0;
		boolean foundSplit = false;
		boolean solverEquivalent = false;
		HashSet<Long> newValHistory = new HashSet<>();
		HashSet<Long> newMajorityHistory = new HashSet<>();
		List<Tuple2<IOSymHashMeta, RunConfiguration>> nlogics;
		List<Long> cnts = extractCnts(logics.stream().map(ent -> ent._2).collect(Collectors.toList()));
		if (debugLevel > 1) {
			logger.info(prefix + "Depth {} Extracted condition-related constants: {}", depth,
					Ranker.countStat(cnts).data);
		}
		do {

			Long newMajority = determineMajorityRamdon(logics.stream().map(ent -> ent._1), newMajorityHistory);
			Long newVal = determineNewVal(cnts, newValHistory);

			if (round == this.maxRound - 1) {
				// last round. sampling cant find result. wee seek for a solver:
				if (debugLevel > 1) {
					logger.info(
							prefix + "Depth {} - Round {} :  the last round. We seek for a solver to find a new value the yield different output.",
							depth, round);
				}
				Long solverNewVal = determineNewValSolver(newMajority, K2, logics, box);
				if (debugLevel > 1) {
					if (solverNewVal != null)
						logger.info(prefix + "Depth {} - Round {} :  We got a new solution from solver {}", depth,
								round, solverNewVal);
					else
						logger.info(prefix + "Depth {} - Round {} : The solver said they are equivalent {}", depth,
								round, solverNewVal);
				}
				if (solverNewVal != null)
					newVal = solverNewVal;
				else
					solverEquivalent = true;
			}

			bucket.newVal = newVal;
			bucket.majority = newMajority;

			nlogics = logics.stream().map(ent -> {

				IOSymHashMeta hm = ent._1;
				RunConfiguration conf = ent._2;
				RunConfigurable confb = ent._2.configurable;

				// get the right configuration
				List<Long> oldInput = hm.input;
				HashMap<String, Tuple2<IOSymHashMeta, RunConfiguration>> newEntries = new HashMap<>();
				if (debugLevel > 3)
					logger.info(prefix + "Old:{} from {}::{}::{}::{}",
							oldInput.stream().map(old -> Long.toHexString(old)).collect(Collectors.toList()),
							hm.varName, confb.blockName, confb.funcName, confb.arch.type);
				for (int i = 0; i < oldInput.size(); ++i)
					if (oldInput.get(i).equals(bucket.majority)) {
						RunConfiguration newConf = conf.copy();
						List<Long> newInput = new ArrayList<>(oldInput);
						newInput.set(i, bucket.newVal);
						RunResult result = newConf.setValue(newInput).run(box);
						// create a new hash meta
						IOSymHashMeta meta = new IOSymHashMeta(newInput, hm.hid, hm.varName, hm.rep);
						Tuple2<IOSymHashMeta, RunConfiguration> newTp = new Tuple2<>(meta, newConf);
						newEntries.put(result.output.value, newTp);
						if (debugLevel > 3)
							logger.info(prefix + "New:{} -> {}",
									newInput.stream().map(old -> Long.toHexString(old)).collect(Collectors.toList()),
									result.output.value);
					}
				if (newEntries.size() > 1) {
					newEntries.remove(K2);
				} else if (newEntries.size() < 1) {
					RunConfiguration newConf = conf.copy();
					RunResult result = newConf.setValue(oldInput).run(box);
					// long result2 = box.run(newConf.subtitute().sNode);
					newEntries.put(result.output.value, new Tuple2<>(ent._1, newConf));
				}

				return newEntries.values();
			}).filter(ent -> ent != null)//
					.flatMap(entries -> entries.stream()).collect(Collectors.toList());

			nlogics.forEach(ent -> {
				// add a leave bucket;
				IOSymHashMeta hm = ent._1;
				RunConfiguration conf = ent._2;
				IOBucketCtn nbucket = splitBuckets.compute(conf.result.output.value,
						(k, v) -> v == null ? new IOBucketCtn(null, null, null, 0) : v);
				nbucket.entries.add(hm);
				nbucket.count = nbucket.entries.size();
			});

			if (debugLevel > 1) {
				int max = splitBuckets.values().stream().mapToInt(bk -> bk.entries.size()).max().getAsInt();
				logger.info(prefix + "Depth {} - Round {} : {} -> {} of size {}; splited bks: max:{}{} {}", depth,
						round, Long.toHexString(newMajority), Long.toHexString(newVal), logics.size(), max,
						splitBuckets.entrySet().stream().filter(ent -> ent.getValue().entries.size() == max)
								.map(ent -> ent.getKey()).collect(Collectors.toList()),
						splitBuckets.entrySet().stream()
								.map(ent -> (ent.getValue().K1 == null ? Integer.toString(ent.getValue().entries.size())
										: Long.toHexString(ent.getValue().K1)))
								.collect(Collectors.toList()));
			}

			// check if it is a good split:
			// if there is a new bucket that is larger than the original one,
			// then it is not a good split.

			// cond1
			// Optional<IOBucketCtn> opt =
			// splitBuckets.values().stream().filter(bk -> bk.entries.size() >=
			// sizeToBeSplit)
			// .findAny();
			// if (!opt.isPresent()) {
			// foundSplit = true;
			// break;
			// }
			// add round

			// if (debugLevel > 2) {
			// splitBuckets.clear();
			// continue;
			// }

			// cond2
			if (splitBuckets.size() > 1) {

				if (splitBuckets.values().stream().filter(ctn -> ctn.entries.size() != logics.size()).findAny()
						.isPresent()) {
					foundSplit = true;
					break;
				}

			}

			round++;
			if (round > this.maxRound - 1)
				break;
			splitBuckets.clear();
		} while (true);

		if (foundSplit)

		{
			bucket.entries.clear();
			index.setBucket(rid, K1, K2, bucket);

			Counter counter = Counter.zero();
			counter.inc();
			splitBuckets.entrySet().forEach(ent -> {
				if (ent.getValue().entries.size() < maxSize || (depth + 1) > this.maxDepth) {
					index.setBucket(rid, bucket.K1, ent.getKey(), ent.getValue());
				} else {
					if (debugLevel > 1)
						logger.info(prefix + "Splitting the #{} of {} logics {}", counter.getVal(), ent.getKey(),
								ent.getValue().entries.size());
					splitBucket(rid, bucket.K1, ent.getKey(), ent.getValue(), box, logicMap, depth + 1);
					counter.inc();
				}
			});

			if (debugLevel > 1)
				logger.info(prefix + "Depth {} - After {} rounds {} splits: {}:{}", depth, round,
						Long.toHexString(bucket.K1), sizeToBeSplit,
						splitBuckets.entrySet().stream()
								.map(ent -> (ent.getValue().K1 == null ? Integer.toString(ent.getValue().entries.size())
										: Long.toHexString(ent.getValue().K1)))
								.collect(Collectors.toList()));

		} else {

			long oldNewVal = bucket.newVal;
			bucket.count = bucket.entries.size();
			bucket.K1 = null;
			bucket.majority = null;
			bucket.newVal = null;
			index.setBucket(rid, K1, K2, bucket);
			IntSummaryStatistics stat = bucket.entries.stream().mapToInt(ent -> ent.input.size()).summaryStatistics();

			logger.warn(
					prefix + "Depth {} - Unable to find good split in {} rounds for {} logics. K1:{} K2:{} Limit:{} In-degree:avg-{}-max-{}-min-{}. {}",
					depth, round, sizeToBeSplit, Long.toHexString(K1), K2, maxSize, stat.getAverage(), stat.getMax(),
					stat.getMin(),
					solverEquivalent ? "Solver said they are equivalent w.r.t. arbitary " + oldNewVal : "");

			if (debugLevel > 2) {

				logger.info(prefix + "Checking for duplicating hims ...");
				if (Ranker
						.countStat(nlogics.stream().map(ent -> ent._2.outputSymbol.cNode.sHash)
								.collect(Collectors.toList()))
						.stream().filter(ent -> ent.score > 1).findAny().isPresent())
					logger.info(prefix + "Found duplication of hids.");
				else
					logger.info(prefix + "No duplication found.");

				logger.warn(prefix + "S-Expressions:");
				nlogics.forEach(ent -> {
					RunConfiguration conf = ent._2;
					logger.warn(prefix + "Depth {} - {}: H:{} I:{} O:{} S:{} F:{} A:{} B:{}", depth,
							conf.outputSymbol.cNode.varName, Integer.toHexString(conf.outputSymbol.cNode.sHash),
							conf.inputAssignments, conf.result.output.value,
							""/*
								 * conf.outputSymbol.cNode.sExpression(conf.
								 * configurable.nodes)
								 */, conf.configurable.funcName, conf.configurable.arch.type, conf.configurable.blockName);
				});
			}
		}

	}

	// get location and block pair as result.
	// location contains the varName information (secondary key)
	public List<LocationQueryResult> locate(long rid, Collection<LocationQuery> targets) {

		// a shared-pool for query (box-ready)
		return targets.parallelStream()
				.map(query -> this.threadPoolExecutor.submit(new BoxReadyThread<LocationQueryResult>(box -> {
					// start with a root node
					IOBucketMeta meta = new IOBucketMeta(rootId, startValue, null, 0);
					// get configurations for this query. (according to some
					// output
					// varName of a basic block)

					List<Location> locs = new ArrayList<>();
					List<RunConfiguration> staticOutputs = new ArrayList<>();

					List<RunConfiguration> confs = query.getConfigurations(box);
					for (RunConfiguration conf : confs) {

						if (conf.inputAssignments == null || conf.inputAssignments.size() > 500)
							continue;

						// set input to be the starting value
						for (int i = 0; i < conf.inputAssignments.size(); ++i) {
							conf.inputAssignments.get(i).value = Long.toHexString(startValue);
						}
						// firstly run for the root node
						conf.run(box);
						if (conf.inputAssignments.size() == 0) {
							// sExpressions that only output static value; not
							// input.
							// we don't need to check its location
							String val = conf.result.output.value;
							if (!val.equals("SKIP") && !val.equals("NXT"))
								staticOutputs.add(conf);
						} else {

							// if (conf.result.output.sym.cNode.sHash ==
							// -846587944)
							// System.out.println("here");

							List<Location> confLocs = locate(rid, conf, meta, box, 0);
							locs.addAll(confLocs);

						}
					}

					LocationQueryResult result = new LocationQueryResult();
					result.query = query;
					result.locations = locs;
					result.staticQueries = staticOutputs;
					return result;
				}))).map(future -> {
					try {
						return future.get();
					} catch (Exception e) {
						logger.error("Failed to execute task for a query.", e);
						return null;
					}
				}).filter(result -> result != null).collect(Collectors.toList());

	}

	/**
	 * Return data structure 'location'
	 * 
	 * @param conf
	 * @param meta
	 * @param box
	 * @return
	 */
	public List<Location> locate(long rid, RunConfiguration conf, IOBucketMeta meta, LaplaceBox box, int depth) {

		// System.out.println(meta.K1 + ":" + conf.result.output.value + " m:" +
		// meta.majority + " n:" + meta.newVal + " " + conf.inputAssignments);

		String K2 = conf.result.output.value;

		IOBucketMeta nxBk = index.loadMeta(rid, meta.K1, K2);

		if (nxBk == null || nxBk.K1 == null || nxBk.newVal == null || nxBk.majority == null) {
			return Arrays.asList(new Location(conf, meta.K1, nxBk, depth));
		}

		// otherwise run for this nxBk
		// set new input
		// we only collect unique output pairs.
		// they derive from the same origional conf.
		HashMap<String, RunConfiguration> newConfs = new HashMap<>();
		List<Long> oldInput = conf.getValue();
		if (nxBk.majority == null) {
			// RunConfiguration newConf = conf.copy();
			// for (int i = 0; i < conf.inputAssignments.size(); ++i) {
			// newConf.inputAssignments.get(i).value =
			// Long.toHexString(nxBk.newVal);
			// }
			// newConfs.add(newConf);
			logger.error(
					"Found a bucket that has NULL majority input value. bk{}:{} Shouldnt be the case. Terminating search at this bruch.",
					meta.K1, K2);
		} else {
			for (int i = 0; i < oldInput.size(); ++i) {
				if (oldInput.get(i).equals(nxBk.majority)) {
					RunConfiguration newConf = conf.copy();
					List<Long> newInput = new ArrayList<>(oldInput);
					newInput.set(i, nxBk.newVal);
					RunResult result = newConf.setValue(newInput).run(box);
					newConfs.put(result.output.value, newConf);
				}
			}
		}
		if (newConfs.size() > 1) {
			newConfs.remove(K2);
		} else if (newConfs.size() < 1) {
			RunConfiguration newConf = conf.copy();
			newConf.setValue(oldInput).run(box);
			newConfs.put(K2, newConf);
		}

		// get resulting buckets
		List<Location> nonEmptyBlks = newConfs.values().stream().map(ncf -> locate(rid, ncf, nxBk, box, depth + 1))
				.filter(pairs -> pairs != null).flatMap(bks -> bks.stream()).filter(pair -> pair.conf != null)
				.collect(Collectors.toList());

		return nonEmptyBlks;
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN.join("detector=", this.getClass().getSimpleName(), "max_depth=", maxDepth,
				"max_bin=", maxSize);
	}

	@Override
	public boolean index(long rid, List<Block> blks, LocalJobProgress progress) {

		StageInfo s1 = progress.nextStage(DifferentialSymbolicIndexer.class,
				"De-duplicating and indexing S-expressions for {} bbs...", blks.size());

		List<BlockLogicWrapper> targets = LogicGraphFactory.translate(blks);
		targets.parallelStream().forEach(graph -> logicFactory.setLogicGraph(rid, graph));

		// check distinction of each sExpression
		// prepare location query.
		// one block has one location query.
		// one location query contains multiple sExpression to be located
		// for this bb.
		Set<Integer> hids = targets.stream().parallel().flatMap(blk -> blk.getLogic().getOutputNodes().stream())
				.map(node -> node.sHash).collect(Collectors.toSet());
		Set<Integer> f_hids = hids.stream().parallel().filter(hid -> !index.checkHid(rid, hid))
				.collect(Collectors.toSet());

		Map<Long, LocationQuery> locQueries = new ConcurrentHashMap<>();
		targets.stream().parallel().forEach(blk -> {
			blk.getLogic().getOutputNodes().stream().parallel().forEach(node -> {
				IOEntry entry = new IOEntry(blk.getBlock(), node.varName);
				if (f_hids.contains(node.sHash)) {
					LocationQuery query = locQueries.get(blk.getBlock().blockId);
					if (query == null) {
						query = new LocationQuery(blk);
						locQueries.put(blk.getBlock().blockId, query);
					}
					query.vars.add(node.varName);
				}
				index.addEntry(rid, node.sHash, entry);
			});
		});
		s1.complete();

		s1 = progress.nextStage(DifferentialSymbolicIndexer.class,
				"Translating logics and locating IO buckets for {} queries...", locQueries.size());
		List<LocationQueryResult> locs = locate(rid, locQueries.values());
		Map<Location, HashMap<Integer, IOSymHashMeta>> loc_hid = new ConcurrentHashMap<>();
		locs.stream().parallel().forEach(result -> {
			Block blk = result.query.blk.getBlock();
			result.locations.stream().forEach(loc -> {
				RunConfiguration conf = loc.conf;
				IOSymHashMeta hm = new IOSymHashMeta(conf.getValue(), conf.outputSymbol.cNode.sHash,
						conf.outputSymbol.cNode.varName, blk.blockId);
				HashMap<Integer, IOSymHashMeta> submap = loc_hid.compute(loc,
						(k, v) -> v != null ? v : new HashMap<>());
				if (!submap.containsKey(hm.hid))
					submap.put(hm.hid, hm);
			});
		});
		loc_hid.entrySet().parallelStream().forEach(ent -> ent.getValue().values()
				.forEach(hm -> index.addHidToBucket(rid, ent.getKey().K1, ent.getKey().conf.result.output.value, hm)));

		s1.updateMsg("Adding static output S-expressions. Directly adding them to HidIndex...");
		locs.stream().parallel().forEach(result -> {
			Block blk = result.query.blk.getBlock();
			result.staticQueries.forEach(conf -> {
				ComputationNode node = conf.outputSymbol.cNode;
				IOEntry entry = new IOEntry(blk, node.varName);
				int newHash = Long.hashCode(Long.parseUnsignedLong(conf.result.output.value, 16));
				index.addEntry(rid, newHash, entry);
			});
			// it is possible that this sHash is new.
			// ideally we need to locate this sHash in table if it is new.
			// however for now we assume that it is not new.
		});
		s1.complete();

		// get buckets to be split
		List<Location> ups = loc_hid.entrySet().stream().filter(
				ent -> (ent.getValue().size() + (ent.getKey().bk == null ? 0 : ent.getKey().bk.count)) > maxSize)
				.sorted((e1, e2) -> {
					int v1 = e1.getValue().size() + (e1.getKey().bk == null ? 0 : e1.getKey().bk.count);
					int v2 = e2.getValue().size() + (e2.getKey().bk == null ? 0 : e2.getKey().bk.count);
					return Integer.compare(v2, v1);
				}).map(tp -> tp.getKey())//
				.collect(Collectors.toList());

		if (debugLevel > 2) {
			List<Integer> ls = ups.stream()
					.map(loc -> new Integer(loc_hid.get(loc).size() + (loc.bk == null ? 0 : loc.bk.count)))
					.collect(Collectors.toList());
			System.out.println(ls);
		}

		if (ups.size() > 0) {
			StageInfo split = progress.nextStage(DifferentialSymbolicIndexer.class,
					"Finding and spliting {} affected I/O buckets...", ups.size());

			IteratorSafeGen<Location> ite = new IteratorSafeGen<>(ups, 1, 1);
			Counter total = Counter.zero();
			new Pool(this.pool_core).start(indx -> {
				LaplaceBox box = SymbolicUtils.createBoxForLocalThread();
				ite.subIterable().forEach(loc -> {
					total.inc();
					split.progress = total.getVal() * 1.0 / ups.size();
					logger.info("splited {}/{}", total.getVal(), ups.size());
					splitBucket(rid, loc, box);
				});
				box.dispose();
			}).waiteForCompletion();
			split.complete();
		}

		// if (debugLevel > 0)
		// this.dump(debugDumpFolder.getAbsolutePath());

		// testing (check if we miss some bucket after splitting)
		// do it again
		// if (debugLevel > 0) {
		// logger.info("DEBUG-ON: checking if we miss any bucket (after
		// split)");
		// locs = locate(targets);
		// locs.stream().filter(loc -> loc._1.bk == null).forEach(loc -> logger
		// .error("Missing bucket at loc {}::{} {}", loc._1.K1,
		// loc._1.conf.result.output.value, loc._1.bk));
		// }

		return true;
	}

	@Override
	public List<Tuple2<Block, Double>> query(long rid, Block sblk, double threshold, int topK) {
		LaplaceBox box = SymbolicUtils.createBoxForLocalThread();

		BlockLogicWrapper target = LogicGraphFactory.translate(sblk);
		LocationQuery query = new LocationQuery(target);
		target.getLogic().getOutputNodes().parallelStream().forEach(out -> query.vars.add(out.varName));

		List<LocationQueryResult> results = locate(rid, Arrays.asList(query));

		Ranker<Long> rank = new Ranker<>(topK);
		HashMap<Long, Double> scores = new HashMap<>();

		assert results.size() == 1;

		LocationQueryResult result = results.get(0);

		result.locations.forEach(loc -> {
			IOBucketCtn bk = index.loadBucket(rid, loc);
			if (bk == null)
				return;
			List<IOSymHashCnt> hCnts = bk.entries.stream().map(hm -> index.loadHashCnt(rid, hm.hid))
					.filter(cnt -> cnt != null).collect(Collectors.toList());
			int tcount = hCnts.stream().mapToInt(cnt -> cnt.entries.size()).sum();
			hCnts.stream().flatMap(cnt -> cnt.entries.stream()).forEach(ent -> {
				double inc = 1.0 / tcount;
				scores.compute(ent.blockId, (k, v) -> v == null ? inc : (v + inc));
			});
		});
		// constant output
		result.staticQueries.forEach(conf -> {
			int newHash = Long.hashCode(Long.parseUnsignedLong(conf.result.output.value, 16));
			IOSymHashCnt hCnt = index.loadHashCnt(rid, newHash);
			if (hCnt != null)
				hCnt.entries.forEach(ent -> {
					double inc = 1.0 / hCnt.entries.size();
					scores.compute(ent.blockId, (k, v) -> v == null ? inc : (v + inc));
				});
		});
		scores.entrySet().forEach(ent -> rank.push(ent.getValue(), ent.getKey()));
		box.dispose();

		return factory.obj_blocks.queryMultipleBaisc(rid, "blockId", new HashSet<>(scores.keySet())).collect().stream()
				.map(blk -> new Tuple2<>(blk, scores.get(blk.blockId))).collect(Collectors.toList());

	}

	@Override
	public void init() {
		index.init();
	}

	@Override
	public void close() {
	}

	private Counter debugRecallCounter = Counter.zero();
	private Counter debugP1Counter = Counter.zero();
	private Counter debugTotalCounter = Counter.zero();

	@Override
	public JavaRDD<Tuple3<Block, Block, Double>> queryAsRdds(long rid, List<Block> targets,
			Set<Tuple2<Long, Long>> links, int topK) {

		// override topk
		// topK = Integer.MAX_VALUE;

		if (debugLevel > 0) {
			logger.info("- - - - - - - - - {}:{} of {} bbs- - - - - - - - - ", targets.get(0).functionName,
					(new File(targets.get(0).binaryName)).getName(), targets.size());
		}

		// long fid = targets.get(0).functionId;
		String fname = targets.get(0).functionName;
		// VexArchitectureType arch = VexArchitecture
		// .convert(factory.getBinaries(targets.get(0).binaryId).get(0).architecture).type;

		// collecting buckets
		ScoringUnit su = this.querySU(rid, targets, links);

		List<F_ScoringUnit> ranks = su.getTopK(topK);

		if (debugLevel > 0) {

			Counter fc = Counter.zero();
			for (int i = 0; i < ranks.size(); i++) {
				F_ScoringUnit candidate = ranks.get(i);
				Function func = factory.obj_functions.querySingleBaisc(rid, candidate.srcfid);
				if (func.functionName.equals(fname)) {
					fc.inc();
					if (i == 0)
						debugP1Counter.inc();
					debugRecallCounter.inc();
				}

				logger.info(" #{} {} {} - {}", //
						String.format("%2d", i), //
						func.functionName.equals(targets.get(0).functionName) ? "*" : "-", //
						StringResources.FORMAT_AR4D.format(candidate.score), String.format("%20s", func.functionName));
			}
			debugTotalCounter.inc();
			logger.info("Summary: Total:{} P1:{} R20:{}", debugTotalCounter.getVal(), debugP1Counter.getVal(),
					debugRecallCounter.getVal());

		}

		// srcId_tar_score: srcbbid_tar_score
		List<Tuple3<Long, Block, Double>> srcId_tar_score = ranks.stream()
				.flatMap(rank -> rank.toSrcBbIdTarScorePairs().stream()).collect(Collectors.toList());

		List<Long> srcBlkIds = srcId_tar_score.stream().map(tp -> tp._1()).collect(Collectors.toList());

		if (debugLevel > 0)
			logger.info("Collected {} srcId_tar pairs. {} unique pairs", srcId_tar_score.size(),
					Sets.newHashSet(srcBlkIds).size());

		JavaPairRDD<Long, Block> srcId_src = factory.obj_blocks.queryMultipleBaisc(rid, "blockId", srcBlkIds)
				.mapToPair(blk -> new Tuple2<>(blk.blockId, blk));

		return sparkInstance.getContext().parallelize(srcId_tar_score)//
				// (srcid, (tar, score))
				.mapToPair(tp3 -> new Tuple2<>(tp3._1(), new Tuple2<>(tp3._2(), tp3._3())))//
				// (srcid, src)
				.join(srcId_src)//
				// after joint: (srcid, ((tar, score), src)
				// 1 2.1.1 2.1.2 2.2
				// return (tar, src, score)
				// return (2.1.1, 2.2, 2.1.2)
				.map(tp2 -> new Tuple3<>(tp2._2()._1()._1, tp2._2()._2(), tp2._2()._1()._2));
	}

	public ScoringUnit querySU(long rid, List<Block> blks, Set<Tuple2<Long, Long>> links) {

		List<BlockLogicWrapper> targets = LogicGraphFactory.translate(blks);

		if (debugLevel > 1) {
			logger.info("- - - - - - - - - {}:{} of {} bbs- - - - - - - - - ", targets.get(0).getBlock().functionName,
					(new File(targets.get(0).getBlock().binaryName)).getName(), targets.size());
		}

		// long fid = targets.get(0).functionId;
		// VexArchitectureType arch = VexArchitecture
		// .convert(factory.getBinaries(targets.get(0).binaryId).get(0).architecture).type;

		// collecting buckets

		List<LocationQuery> queries = targets.stream().parallel().map(target -> {
			LocationQuery query = new LocationQuery(target);
			target.getLogic().getOutputNodes().forEach(out -> query.vars.add(out.varName));
			return query;
		}).collect(Collectors.toList());
		List<LocationQueryResult> results = locate(rid, queries);

		if (debugLevel > 1)
			logger.info("Located buckets.");

		if (debugLevel > 1)
			logger.info("Collected {} locations for {} queries",
					results.stream().mapToInt(result -> result.locations.size()).sum(), results.size()//
			);

		// structure:
		// temp fix for release purpose:
		// ScoringUnit su = new ScoringUnit(fid);
		ScoringUnit su = new ScoringUnit(-1);
		HashMap<Integer, IOSymHashCnt> hidCache = new HashMap<>();
		Map<Location, IOBucketCtn> bks = new HashMap<>();
		List<Tuple2<Location, IOBucketCtn>> ls = results.parallelStream().flatMap(res -> res.locations.stream())
				.distinct().filter(loc -> {
					IOBucketMeta meta = loc.bk; // index.loadMeta(loc.K1,
												// loc.conf.result.output.value);
					// logger.info("location {}::{} of depth {} with meta {}",
					// loc.K1, loc.conf.result.output.value,
					// loc.depth, meta == null ? "NL" : meta.count);
					return meta != null && meta.count < 800;
				}).filter(loc -> loc != null).map(loc -> new Tuple2<>(loc, index.loadBucket(rid, loc)))
				.filter(tp -> tp._2 != null && tp._1 != null).collect(Collectors.toList());
		ls.forEach(tp -> bks.put(tp._1, tp._2));

		results.stream().forEach(result -> {
			Block tar = result.query.blk.getBlock();
			result.locations.stream().forEach(loc -> {
				IOBucketCtn bk = bks.get(loc);
				String varName = loc.conf.result.output.sym.cNode.varName;
				if (bk != null && bk.entries.size() < 1000) {
					Set<Integer> hids = bk.entries.stream().map(hm -> hm.hid).collect(Collectors.toSet());
					List<IOEntry> ioEntries = hids.stream().map(hid -> {
						IOSymHashCnt hbk;
						synchronized (hidCache) {
							if (!hidCache.containsKey(hid)) {
								hbk = index.loadHashCnt(rid, hid);
								hidCache.put(hid, hbk);
							} else
								hbk = hidCache.get(hid);
							return hbk;
						}
					}).filter(cnt -> cnt != null).flatMap(cnt -> cnt.entries.stream()).collect(Collectors.toList());
					// tmp hack. causing error
					if (ioEntries.size() < 1000) {
						Set<Long> fids = ioEntries.stream().filter(ioe -> ioe != null).map(ioe -> ioe.functionId)
								.collect(Collectors.toSet());
						int size = fids.size();
						ioEntries.stream().forEach(entry -> {
							su.add(varName, tar, entry, size);
						});
					}
				}
			});

			result.staticQueries.parallelStream().forEach(conf -> {
				// for (RunConfiguration conf : result.staticQueries) {
				if (conf.result.output.value.length() < 2)
					return;
				Integer newHash = Long.hashCode(Long.parseUnsignedLong(conf.result.output.value, 16));
				IOSymHashCnt hCnt;
				synchronized (hidCache) {
					if (!hidCache.containsKey(newHash)) {
						hCnt = index.loadHashCnt(rid, newHash);
						hidCache.put(newHash, hCnt);
					} else
						hCnt = hidCache.get(newHash);
				}
				String varName = conf.outputSymbol.cNode.varName;
				// logger.info("Fetching static value: {} that contains {}
				// entries.", conf.result.output.value,
				// hCnt == null ? "NL" : hCnt.entries.size());
				if (hCnt != null && hCnt.entries.size() < 1000) {
					Set<Long> fids = hCnt.entries.stream().map(ioe -> ioe.functionId).collect(Collectors.toSet());
					int size = fids.size();
					hCnt.entries.forEach(ent -> {
						su.add(varName, tar, ent, size);
					});
				}
			});
			// }
		});

		return su;

	}

	@Override
	public boolean dump(String path) {
		// index.stat();
		// return true;
		return index.dump(path);
	}

}
