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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;

import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import scala.Tuple2;
import scala.Tuple3;
import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.Counter;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.Indexer;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocks;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocksImpl2;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocksImpl3;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.utils.SubgraphBlocks.HashedLinkedBlock;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class FunctionSubgraphDetector extends FunctionCloneDetector implements Serializable {

	private static final long serialVersionUID = -3074769950074408720L;

	private static Logger logger = LoggerFactory.getLogger(FunctionSubgraphDetector.class);

	private Indexer<Block> indexer;

	private int blockLengthLimit = 1;
	private int debugLevel = 0;
	private double basicCloneThreshold = 0.05;
	private SparkInstance spark = null;
	public boolean specialSingleBlkFuncSearch = true;
	public int fixTopK = -1;

	public FunctionSubgraphDetector(AsmObjectFactory factory, SparkInstance instance, Indexer<Block> indexer,
			int blockLengthLimit, boolean debug) {
		super(factory);
		this.blockLengthLimit = blockLengthLimit;
		if (debug) {
			debugLevel = 1;
		}
		this.indexer = indexer;
		this.spark = instance;
	}

	ListMultimap<Long, String> reverse = ArrayListMultimap.create();

	@Override
	protected void indexFuncsToBeImplByChildren(long rid, List<Binary> binaries, LocalJobProgress progress)
			throws Exception {

		List<Block> blks = binaries.stream().flatMap(bin -> bin.functions.stream()).flatMap(func -> {
			int size = 0;
			for (Block block : func)
				if (block.getAsmLines().size() > blockLengthLimit)
					size += block.getAsmLines().size();
			for (Block block : func)
				block.peerSize = size;
			// block.peerSize = func.blocks.size();
			return func.blocks.stream().filter(blk -> blk.getAsmLines().size() > blockLengthLimit);
		}).collect(Collectors.toList());

		// List<Block> blks = binaries//
		// .stream()//
		// .flatMap(bin -> bin.functions//
		// .stream()) //
		// .flatMap(func -> func.blocks//
		// .stream())//
		// .filter(blk -> blk.getAsmLines().size() > blockLengthLimit)//
		// .collect(Collectors.toList());

		indexer.index(rid, blks, progress);
	}

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
			double threshold, int topK, boolean avoidSameBinary) throws Exception {

		if (fixTopK > 0)
			topK = fixTopK;

		// detection clones of the given function:
		// calculate buckets of its blocks:

		ArrayList<Block> vBlks = new ArrayList<>();

		HashSet<Tuple2<Long, Long>> links = new HashSet<>();
		Counter finalFuncLength = Counter.zero();
		for (Block blk : function) {
			int blkLength = blk.getAsmLines().size();
			// if(blkLength != blk.codesSize)
			// logger.info("Incosistnent size {} vs {}", blkLength, blk.codesSize);
			// System.out.println(blk.blockName + "," + blk.codesSize);
			if (blkLength > blockLengthLimit) {
				vBlks.add(blk);
				finalFuncLength.inc(blkLength);
			}
		}
		Set<Long> vBlkIds = vBlks.stream().map(blk -> blk.blockId).collect(Collectors.toSet());
		for (Block blk : vBlks) {
			blk.callingBlocks.stream().filter(callee -> vBlkIds.contains(callee))
					.forEach(callee -> links.add(new Tuple2<Long, Long>(blk.blockId, callee)));
			links.add(new Tuple2<>(blk.blockId, blk.blockId));
		}

		// if (debugLevel > 0)
		// logger.info("{} {} bbs of length {}", function.functionName,
		// vBlkIds.size(), finalFuncLength.count);

		// final int minFuncLength = (int) Math.ceil(funcLength * threadshold);

		List<FunctionCloneEntry> results = null;

		if (specialSingleBlkFuncSearch && vBlks.size() == 1) {
			// if (false) {
			// indexer.queryAsRdd(target, threshold, topK)
			List<Tuple2<Block, Double>> blks = indexer.query(rid, vBlks.get(0), threshold, topK);
			results = blks.stream().map(ent -> {
				FunctionCloneEntry entry = new FunctionCloneEntry();
				entry.binaryId = ent._1.binaryId;
				entry.binaryName = ent._1.binaryName;
				entry.functionId = ent._1.functionId;
				entry.functionName = ent._1.functionName;
				entry.similarity = ent._2;
				Tuple3<Long, Long, Double> tp = new Tuple3<Long, Long, Double>(vBlks.get(0).blockId, ent._1.blockId,
						ent._2);
				entry.clonedParts.add(new HashSet<>(Arrays.asList(tp)));
				return entry;
			}).collect(Collectors.toList());

		} else {

			// convert (tar, src, score) to (srcfuncid, (tar, src, score))
			JavaRDD<Tuple2<Long, Tuple3<Block, Block, Double>>> b_to_b = indexer//
					.queryAsRdds(rid, vBlks, links, topK)//
					.filter(tuple -> !avoidSameBinary || (tuple._2().binaryId != function.binaryId))
					.map(tuple -> new Tuple2<>(tuple._2().functionId, tuple));

			int fc = finalFuncLength.count;
			if (!spark.localMode) {
				// (keyed: srcfuncid -> (tar, src, score)
				JavaPairRDD<Long, Tuple3<Block, Block, Double>> func_sblks = b_to_b.mapToPair(t -> {
					return new Tuple2<>(t._1, new Tuple3<>(t._2._1(), t._2._2(), t._2._3()));
				});
				// data locality
				results = func_sblks.groupByKey().map(tp -> {
					FunctionCloneEntry sbi = SubgraphBlocksImpl3.mergeSingles2(fc, null);
					return sbi;
				}).collect();
			} else {

				ArrayListMultimap<Long, Tuple3<Block, Block, Double>> matchedBlocksBySourceFunction =
						ArrayListMultimap.create();

				b_to_b.toLocalIterator().forEachRemaining(tp2 -> matchedBlocksBySourceFunction.put(tp2._1(), tp2._2()));

				// logger.info("started {}", function.functionName);
				results = matchedBlocksBySourceFunction.keySet().stream().parallel().map(tp -> {
					return SubgraphBlocksImpl3.mergeSingles2(fc, matchedBlocksBySourceFunction.get(tp));
				}).collect(Collectors.toList());

				// Warning: may cause OOM
				// logger.info("Dumping indexs");
				// indexer.dump("C:\\delivery\\tmp\\");
				// logger.info("finished {}", function.functionName);
			}

			// FIXME: (KAM1N0-206) filter topK results, right now we may have up to topK*3 results
		}

		return results;
	}

	public String params() {
		return StringResources.JOINER_TOKEN.join("detector=", this.getClass().getSimpleName(), "blockLengthLimit=",
				blockLengthLimit, "basicCloneThreshold=", basicCloneThreshold, "indexer=", indexer.params());
	}

	@Override
	public void init() throws Exception {
		indexer.init();
	}

	@Override
	public void close() throws Exception {
		indexer.close();
	}

	@Override
	public boolean dump(String path) {
		return this.indexer.dump(path);
	}

	@Override
	public void clear(long rid) {
		this.indexer.clear(rid);
	}
}
