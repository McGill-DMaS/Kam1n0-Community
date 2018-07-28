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
package ca.mcgill.sis.dmas.nlp.model.astyle._1_original;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.IteratorSafeGen;
import ca.mcgill.sis.dmas.io.collection.Pool;
import ca.mcgill.sis.dmas.nlp.model.astyle.GradientProgress;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle.NodeWord;
import ca.mcgill.sis.dmas.nlp.model.astyle.Param;
import ca.mcgill.sis.dmas.nlp.model.astyle.RandL;
import static ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities.*;
import static java.util.stream.Collectors.*;

import java.util.ArrayList;

import static java.lang.Math.sqrt;

public class LearnerAsm2VecEXP {

	private static Logger logger = LoggerFactory.getLogger(LearnerAsm2VecEXP.class);

	public static class Asm2VecNewParam extends Param {
		private static final long serialVersionUID = -817341338942724187L;
		public int min_freq = 3;
		public int vec_dim = 200;
		public double optm_subsampling = 1e-4;
		public double optm_initAlpha = 0.05;
		public int optm_window = 8;
		public int optm_negSample = 25;
		public int optm_parallelism = 1;
		public int optm_iteration = 1;
		public int optm_aphaUpdateInterval = 10000;

	}

	public Consumer<Integer> iterationHood = null;

	public Map<String, NodeWord> vocab = null;
	public Map<String, NodeWord> trainDocMap = null;
	public List<NodeWord> vocabL = null;
	public int[] pTable;
	public transient volatile double alpha;
	public transient volatile long tknCurrent;
	public transient volatile long tknLastUpdate;
	public transient volatile int iteration = 0;
	public volatile long tknTotal;
	public volatile boolean debug = true;
	public Asm2VecNewParam param;

	private void preprocess(Iterable<FuncTokenized> funcs) {

		vocab = null;

		// frequency map:
		final HashMap<String, Long> counter = new HashMap<>();
		funcs.forEach(func -> func.forEach(blk -> blk
				.forEach(token -> counter.compute(token.trim().toLowerCase(), (w, c) -> c == null ? 1 : c + 1))));

		// add additional word (for /n)
		counter.put("</s>", Long.MAX_VALUE);

		// create word nodes (matrix)
		vocab = counter.entrySet().stream().parallel().filter(en -> en.getValue() >= param.min_freq)
				.collect(toMap(Map.Entry::getKey, p -> new NodeWord(p.getKey(), p.getValue())));

		// total valid word count
		tknTotal = vocab.values().stream().filter(w -> !w.token.equals("</s>")).mapToLong(w -> w.freq).sum();

		// vocabulary list (sorted)
		vocabL = vocab.values().stream().sorted((a, b) -> b.token.compareTo(a.token))
				.sorted((a, b) -> Double.compare(b.freq, a.freq)).collect(toList());

		// reset frequency for /n
		vocabL.get(0).freq = 0;

		// initialize matrix:
		RandL rd = new RandL(1);
		vocabL.stream().forEach(node -> node.init(param.vec_dim, rd));

		// sub-sampling probability
		if (param.optm_subsampling > 0) {
			double fcount = param.optm_subsampling * tknTotal;
			vocabL.stream().parallel().forEach(w -> w.samProb = (sqrt(w.freq / fcount) + 1) * fcount / w.freq);
		}

		pTable = createPTbl(vocabL, (int) 1e8, 0.75);

		// if (debug)
		logger.info("Vocab {}; Total {};", vocabL.size(), tknTotal);

		trainDocMap = new HashMap<>();
		funcs.forEach(func -> trainDocMap.put(func.id, new NodeWord(func.id, 1)));
		trainDocMap.values().forEach(node -> node.init(this.param.vec_dim, rd));
	}

	public static class ShuffleWrapper<T> implements Iterable<T> {
		private List<T> ls;

		public ShuffleWrapper(List<T> ls) {
			this.ls = ls;
		}

		@Override
		public Iterator<T> iterator() {
			Collections.shuffle(this.ls);
			return this.ls.iterator();
		}
	}

	private void gradientDecend(final List<FuncTokenized> funcs, Map<String, NodeWord> funcMap, long numTkns,
			long alphaUpdateInterval, boolean updateWordVec) throws InterruptedException, ExecutionException {
		tknLastUpdate = 0;
		tknCurrent = 0;
		// training
		GradientProgress p = new GradientProgress(numTkns * param.optm_iteration);
		if (debug)
			p.start(logger);

		// thread-safe batch consumer generator:
		final IteratorSafeGen<FuncTokenized> gen = new IteratorSafeGen<>(new ShuffleWrapper<>(funcs), 100,
				param.optm_iteration, iterationHood, ite -> {
					this.iteration = ite;
					logger.info("Iteration {}", ite);
				});

		new Pool(param.optm_parallelism).start(indx -> {
			RandL rl = new RandL(indx);
			Random rd = new Random(indx);
			double[] bfIn = new double[param.vec_dim], bfNeul1e = new double[param.vec_dim];
			gen.subIterable().forEach(func -> {
				// update alpha:
				if (tknCurrent - tknLastUpdate > alphaUpdateInterval) {
					alpha = param.optm_initAlpha * (1.0 - 1.0 * tknCurrent / (numTkns * param.optm_iteration + 1));
					alpha = alpha < param.optm_initAlpha * 0.00001 ? param.optm_initAlpha * 0.00001 : alpha;
					if (debug)
						p.report(logger, tknCurrent, alpha);
					tknLastUpdate = tknCurrent;
				}

				if (!funcMap.containsKey(func.id)) {
					logger.error("Critical error. Doc node not found {}", func);
					return;
				}

				iterate(func.linearLayout(), funcMap.get(func.id), rl, bfIn, bfNeul1e, updateWordVec);
			});
		}).waiteForCompletion();
		if (debug)
			p.complete(logger);
	}

	private void iterate(List<List<String>> in_strs, NodeWord docNode, RandL rl, double[] bfIn, double[] bfNeul1e,
			boolean updateWordVec) {

		List<List<NodeWord>> ins = in_strs.stream()
				.map(in -> in.stream().map(tkn -> vocab.get(tkn.trim().toLowerCase()))//
						.filter(notNull)//
						.peek(node -> tknCurrent++)//
						.filter(n -> in_strs.size() < 2 || n.samProb >= rl.nextF()) //
						.collect(toList()))
				.filter(in -> in.size() > 0)//
				.collect(Collectors.toList());

		for (int i = 0; i < ins.size(); ++i) {
			List<NodeWord> context = new ArrayList<>();
			// if (i > 0)
			// context.addAll(ins.get(i - 1));
			// if (i < ins.size() - 1)
			// context.addAll(ins.get(i + 1));
			for (int j = 0; j < ins.get(i).size(); ++j) {
				NodeWord target = ins.get(i).get(j);
				EntryPair<NodeWord, List<NodeWord>> cont = new EntryPair<>(target, context);
				pred(cont, rl, docNode, bfIn, bfNeul1e, updateWordVec);
			}
		}
	}

	private void pred(EntryPair<NodeWord, List<NodeWord>> cont, RandL rl, NodeWord docNode, double[] bfIn,
			double[] neul1e, boolean updateWordVec) {
		double[] errors;
		errors = neul1e;
		Arrays.fill(bfIn, 0.0);
		Arrays.fill(errors, 0.0);
		cont.value.stream().forEach(src -> add(bfIn, src.neuIn));
		add(bfIn, docNode.neuIn);
		// div(bfIn, cont.value.size() + 1);
		ngSamp(cont.key, bfIn, errors, rl, updateWordVec, null);
		if (updateWordVec)
			cont.value.stream().forEach(src -> add(src.neuIn, errors));
		add(docNode.neuIn, errors);
	}

	private void ngSamp(NodeWord tar, double[] in, double[] neul1e, RandL rl, boolean updateWordVec,
			List<NodeWord> exceptions) {
		for (int i = 0; i < param.optm_negSample + 1; ++i) {
			double label;
			double[] out;
			// NodeWord target;
			if (i == 0) {
				label = 1;
				out = tar.neuOut;
			} else {
				label = 0;
				int tarInd = (int) Long.remainderUnsigned(rl.nextR() >>> 16, pTable.length);
				NodeWord rtar = vocabL.get(pTable[tarInd]);
				if (rtar == tar || (exceptions != null && exceptions.contains(rtar)))
					continue;
				out = rtar.neuOut;
			}
			double f = exp(dot(in, out));
			double g = (label - f) * alpha;
			dxpay(neul1e, out, g);
			if (updateWordVec)
				dxpay(out, in, g);
		}
	}

	public void train(List<FuncTokenized> funcs) throws InterruptedException, ExecutionException {
		alpha = param.optm_initAlpha;
		preprocess(funcs);
		gradientDecend(funcs, trainDocMap, tknTotal, param.optm_aphaUpdateInterval, true);
	}

	public Map<String, double[]> infer(Iterable<FuncTokenized> funcs) {
		alpha = param.optm_initAlpha;
		this.debug = false;
		try {
			Map<String, double[]> result = new HashMap<>();
			StreamSupport.stream(funcs.spliterator(), false)//
					.map(doc -> trainDocMap.get(doc.id))//
					.filter(node -> node != null)//
					.forEach(node -> result.put(node.token, normalize(cp(node.neuIn))));

			return result;
		} catch (Exception e) {
			logger.info("Failed to learn new doc vector.", e);
			return null;
		}
	}

	public WordEmbedding produce() {
		WordEmbedding embedding = new WordEmbedding();
		embedding.vocabL = vocabL.stream().map(node -> new EntryPair<>(node.token, convertToFloat(node.neuIn)))
				.collect(toList());
		try {
			embedding.param = (new ObjectMapper()).writeValueAsString(this.param);
		} catch (Exception e) {
			logger.error("Failed to serialize the parameter. ", e);
		}
		return embedding;
	}

	int last_doc_vec_map_ite = -1;

	public Map<String, double[]> produceNormalizedDocEmbdCpy() {
		Map<String, double[]> embd = this.produceDocEmbdCpy();
		return MathUtilities.normalize(embd);
	}

	public Map<String, double[]> produceDocEmbdCpy() {
		return trainDocMap.entrySet().stream().collect(toMap(ent -> ent.getKey(), ent -> cp(ent.getValue().neuIn)));
	}

	public LearnerAsm2VecEXP(Asm2VecNewParam param) {
		this.param = param;
	}
}
