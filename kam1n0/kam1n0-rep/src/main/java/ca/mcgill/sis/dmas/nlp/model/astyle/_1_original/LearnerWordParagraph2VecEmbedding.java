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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import ca.mcgill.sis.dmas.nlp.model.astyle.Document;
import ca.mcgill.sis.dmas.nlp.model.astyle.GradientProgress;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle.NodeWord;
import ca.mcgill.sis.dmas.nlp.model.astyle.Param;
import ca.mcgill.sis.dmas.nlp.model.astyle.RandL;
import ca.mcgill.sis.dmas.nlp.model.astyle.Sentence;

import static ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities.*;
import static java.util.stream.Collectors.*;

import java.util.ArrayList;

import static java.lang.Math.sqrt;

public class LearnerWordParagraph2VecEmbedding {

	private static Logger logger = LoggerFactory.getLogger(LearnerWordParagraph2VecEmbedding.class);

	public static class P2VParam extends Param {
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
		public boolean optm_cbw = true;
		public boolean vec_concate = false;

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
	public P2VParam param;

	private void preprocess(Iterable<Document> documents) {

		vocab = null;

		// frequency map:
		final HashMap<String, Long> counter = new HashMap<>();
		documents.forEach(doc -> doc.forEach(sent -> sent
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
		if (param.optm_cbw == false || (param.optm_cbw == true && param.vec_concate == false))
			vocabL.stream().forEach(node -> node.init(param.vec_dim, rd));
		else {
			vocabL.stream().forEach(node -> node.initInLayer(param.vec_dim, rd));
			vocabL.stream().forEach(node -> node.initOutLayer(param.vec_dim * (param.optm_window * 2 + 1)));
			NOPE.initInLayer(param.vec_dim, rd);
		}

		// sub-sampling probability
		if (param.optm_subsampling > 0) {
			double fcount = param.optm_subsampling * tknTotal;
			vocabL.stream().parallel().forEach(w -> w.samProb = (sqrt(w.freq / fcount) + 1) * fcount / w.freq);
		}

		pTable = createPTbl(vocabL, (int) 1e8, 0.75);

		// if (debug)
		logger.info("Vocab {}; Total {};", vocabL.size(), tknTotal);

		trainDocMap = new HashMap<>();
		documents.forEach(doc -> trainDocMap.put(doc.id, new NodeWord(doc.id, 1)));
		trainDocMap.values().forEach(node -> node.init(this.param.vec_dim, rd));
	}

	private void gradientDecend(final Iterable<Document> documents, Map<String, NodeWord> docMap, long numTkns,
			long alphaUpdateInterval, boolean updateWordVec) throws InterruptedException, ExecutionException {
		tknLastUpdate = 0;
		tknCurrent = 0;
		// training
		GradientProgress p = new GradientProgress(numTkns * param.optm_iteration);
		if (debug)
			p.start(logger);

		// threadsafe batch consumer generator:
		final IteratorSafeGen<Document> gen = new IteratorSafeGen<>(documents, 100, param.optm_iteration, iterationHood,
				ite -> {
					// update alpha:
					// alpha = param.optm_initAlpha * (1.0 - 1.0 * tknCurrent /
					// (numTkns * param.optm_iteration + 1));
					// alpha = alpha < param.optm_initAlpha * 0.0001 ?
					// param.optm_initAlpha * 0.0001 : alpha;
					// if (debug)
					// p.report(logger, tknCurrent, alpha);
					// tknLastUpdate = tknCurrent;
					// logger.info("alpha: {}", alpha);
					this.iteration = ite;
				});

		new Pool(param.optm_parallelism).start(indx -> {
			RandL rl = new RandL(indx);
			double[] bfIn = new double[param.vec_dim], bfNeul1e = new double[param.vec_dim];
			gen.subIterable().forEach(doc -> {
				for (Sentence sent : doc) {

					// update alpha:
					if (tknCurrent - tknLastUpdate > alphaUpdateInterval) {
						alpha = param.optm_initAlpha * (1.0 - 1.0 * tknCurrent / (numTkns * param.optm_iteration + 1));
						alpha = alpha < param.optm_initAlpha * 0.00001 ? param.optm_initAlpha * 0.00001 : alpha;
						if (debug)
							p.report(logger, tknCurrent, alpha);
						tknLastUpdate = tknCurrent;
					}

					// dictionary lookup & sub-sampling
					List<NodeWord> nsent = Arrays.stream(sent.tokens)
							//
							.map(tkn -> vocab.get(tkn.trim().toLowerCase()))//
							.filter(notNull)//
							.peek(node -> tknCurrent++)//
							.filter(n -> n.samProb >= rl.nextF()) //
							.collect(toList());

					if (!docMap.containsKey(doc.id)) {
						logger.error("Critical error. Doc node not found {}", doc);
						return;
					}

					iterate(nsent, docMap.get(doc.id), rl, bfIn, bfNeul1e, updateWordVec);
				}
			});
		}).waiteForCompletion();
		if (debug)
			p.complete(logger);
	}

	// negative sampling
	private static NodeWord NOPE = new NodeWord("NOPE", 1);

	private void iterate(List<NodeWord> nsent, NodeWord docNode, RandL rl, double[] bfIn, double[] bfNeul1e,
			boolean updateWordVec) {
		RandL reducedWind = rl;
		if (param.optm_cbw && param.vec_concate)
			reducedWind = null;
		slidingWnd(nsent, param.optm_window, reducedWind, null).forEach(cont -> {
			if (param.optm_cbw)
				cbw(cont, rl, docNode, bfIn, bfNeul1e, updateWordVec);
			else
				skg(cont, rl, docNode, bfNeul1e, updateWordVec);
		});
	}

	private void skg(EntryPair<NodeWord, List<NodeWord>> cont, RandL rl, NodeWord docNode, double[] neul1e,
			boolean updateWordVec) {
		cont.value.add(cont.key);
		// System.out.println(cont);
		cont.value.stream().forEach(tar -> {
			Arrays.fill(neul1e, 0.0);
			ngSamp(tar, docNode.neuIn, neul1e, rl, updateWordVec, cont.value);
			add(docNode.neuIn, neul1e);
		});
	}

	private void cbw(EntryPair<NodeWord, List<NodeWord>> cont, RandL rl, NodeWord docNode, double[] bfIn,
			double[] neul1e, boolean updateWordVec) {
		// System.out.println(cont);
		double[] errors;
		if (param.vec_concate) {
			errors = new double[param.vec_dim * (param.optm_window * 2 + 1)];
		} else {
			errors = neul1e;
		}
		Arrays.fill(bfIn, 0.0);
		Arrays.fill(errors, 0.0);
		if (cont.value.size() > 0) {
			double[] in;
			if (param.vec_concate) {
				ArrayList<double[]> inList = new ArrayList<>();
				cont.value.stream().map(node -> node.neuIn).forEachOrdered(inList::add);
				inList.add(docNode.neuIn);
				in = MathUtilities.concate(inList);
			} else {
				cont.value.stream().forEach(src -> add(bfIn, src.neuIn));
				add(bfIn, docNode.neuIn);
				// div(bfIn, cont.value.size() + 1);
				in = bfIn;
			}
			ngSamp(cont.key, in, errors, rl, updateWordVec, null);
			if (param.vec_concate) {
				if (updateWordVec)
					for (int i = 0; i < cont.value.size(); ++i)
						for (int j = 0; j < param.vec_dim; ++j)
							cont.value.get(i).neuIn[j] += errors[i * param.vec_dim + j];
				for (int j = 0; j < param.vec_dim; ++j)
					docNode.neuIn[j] += errors[(cont.value.size()) * param.vec_dim + j];
			} else {
				if (updateWordVec)
					cont.value.stream().forEach(src -> add(src.neuIn, errors));
				add(docNode.neuIn, errors);
			}
		}
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

	public void train(Iterable<Document> docs) throws InterruptedException, ExecutionException {
		alpha = param.optm_initAlpha;
		preprocess(docs);
		gradientDecend(docs, trainDocMap, tknTotal, param.optm_aphaUpdateInterval, true);
	}

	public Map<String, double[]> infer(Iterable<Document> docs) {
		alpha = param.optm_initAlpha;
		try {
			Iterable<Document> fdocs = Iterables.filter(docs, doc -> !trainDocMap.containsKey(doc.id));

			HashMap<String, NodeWord> inferDocMap = new HashMap<>();
			fdocs.forEach(doc -> inferDocMap.put(doc.id, new NodeWord(doc.id, 1)));
			RandL rd = new RandL(1);
			inferDocMap.values().forEach(node -> node.init(this.param.vec_dim, rd));

			long tknTotalInDocs = StreamSupport.stream(fdocs.spliterator(), false)
					.flatMap(doc -> doc.sentences.stream()).flatMap(sent -> Arrays.stream(sent.tokens))
					.filter(tkn -> vocab.containsKey(tkn)).count();

			gradientDecend(fdocs, inferDocMap, tknTotalInDocs, 0, false);
			Map<String, double[]> result = inferDocMap.entrySet()//
					.stream()//
					.map(ent -> new EntryPair<>(ent.getKey(), ent.getValue().neuIn))
					.collect(Collectors.toMap(ent -> ent.key, ent -> normalize(cp(ent.value))));

			StreamSupport.stream(docs.spliterator(), false)//
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
		return trainDocMap.entrySet().stream()
				.collect(toMap(ent -> ent.getKey(), ent -> normalize(cp(ent.getValue().neuIn))));
	}

	public LearnerWordParagraph2VecEmbedding(P2VParam param) {
		this.param = param;
	}
}
