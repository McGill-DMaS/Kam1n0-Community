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

import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.io.LineSequenceWriter;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.IteratorSafeGen;
import ca.mcgill.sis.dmas.io.collection.Pool;
import ca.mcgill.sis.dmas.nlp.model.astyle.Document;
import ca.mcgill.sis.dmas.nlp.model.astyle.GradientProgress;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;
import ca.mcgill.sis.dmas.nlp.model.astyle.NodeWord;
import ca.mcgill.sis.dmas.nlp.model.astyle.RandL;
import ca.mcgill.sis.dmas.nlp.model.astyle.Sentence;

import static ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities.*;
import static java.util.stream.Collectors.*;
import static java.lang.Math.sqrt;

public class LearnerWordEmbedding {

	private static Logger logger = LoggerFactory.getLogger(LearnerWordEmbedding.class);

	public static class Word2VecParam extends ca.mcgill.sis.dmas.nlp.model.astyle.Param {
		private static final long serialVersionUID = -817341338942724187L;
		public int min_freq = 5;
		public int vec_dim = 200;
		public double optm_subsampling = 1e-4;
		public double optm_initAlpha = 0.05;
		public int optm_window = 8;
		public int optm_negSample = 25;
		public int optm_parallelism = 1;
		public int optm_iteration = 1;
		public boolean optm_cbw = true;
		public String save_vocab = null;
	}

	public Consumer<Integer> iterationHood = null;

	private Map<String, NodeWord> vocab = null;
	private List<NodeWord> vocabL = null;
	private int[] pTable;
	private volatile double alpha;
	private volatile long tknCurrent;
	private volatile long tknLastUpdate;
	private volatile long tknTotal;
	public volatile boolean debug = true;
	public Word2VecParam param;

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
		vocabL.stream().forEach(node -> node.init(param.vec_dim, rd));

		// sub-sampling probability
		if (param.optm_subsampling > 0) {
			double fcount = param.optm_subsampling * tknTotal;
			vocabL.stream().parallel().forEach(w -> w.samProb = (sqrt(w.freq / fcount) + 1) * fcount / w.freq);
		}

		pTable = createPTbl(vocabL, (int) 1e8, 0.75);

		if (param.save_vocab != null) {
			try {
				LineSequenceWriter writer = Lines.getLineWriter(param.save_vocab, false);
				vocabL.forEach(node -> writer.writeLine(node.token, Long.toString(node.freq)));
				writer.close();
			} catch (Exception e) {
				logger.error("Failed to save vocab.", e);
			}
		}

		logger.info("Vocab {}; Total {};", vocabL.size(), tknTotal);
	}

	public HashMap<String, double[]> inference(Iterable<Document> docs) {
		HashMap<String, double[]> vectorMap = new HashMap<>();
		docs.forEach(doc -> {
			double[] v = new double[this.param.vec_dim];
			int counter = 0;
			for (Sentence set : doc) {
				for (String token : set) {
					NodeWord wm = this.vocab.get(token.trim().toLowerCase());
					if (wm != null) {
						counter++;
						MathUtilities.add(v, wm.neuIn);
					}
				}
			}
			MathUtilities.div(v, counter);
			vectorMap.put(doc.id, v);
		});
		return vectorMap;
	}

	private void gradientDecend(final Iterable<Document> documents) throws InterruptedException, ExecutionException {
		tknLastUpdate = 0;
		tknCurrent = 0;
		// training
		GradientProgress p = new GradientProgress(tknTotal * param.optm_iteration);
		p.start(logger);

		// threadsafe batch consumer generator:
		final IteratorSafeGen<Document> gen = new IteratorSafeGen<>(documents, 100, param.optm_iteration,
				iterationHood);

		new Pool(param.optm_parallelism).start(indx -> {
			RandL rl = new RandL(indx);
			double[] bfIn = new double[param.vec_dim], bfNeul1e = new double[param.vec_dim];
			gen.subIterable().forEach(doc -> {
				doc.forEach(sent -> {

					// update alpha:
					if (tknCurrent - tknLastUpdate > 10000) {
						alpha = param.optm_initAlpha * (1.0 - 1.0 * tknCurrent / (tknTotal * param.optm_iteration + 1));
						alpha = alpha < param.optm_initAlpha * 0.0001 ? param.optm_initAlpha * 0.0001 : alpha;
						if (debug)
							p.report(logger, tknCurrent, alpha);
						tknLastUpdate = tknCurrent;
					}

					// dictionary lookup & sub-sampling
					List<NodeWord> nsent = Arrays.stream(sent.tokens)//
							.map(tkn -> vocab.get(tkn.trim().toLowerCase()))//
							.filter(notNull)//
							.peek(node -> tknCurrent++)//
							.filter(n -> n.samProb >= rl.nextF()) //
							.collect(toList());

					iterate(nsent, rl, bfIn, bfNeul1e);
				});
			});
		}).waiteForCompletion();
		p.complete(logger);
	}

	public static DecimalFormat FORMAT_1R6D = new DecimalFormat("0.000000");

	// negative sampling
	private void iterate(List<NodeWord> nsent, RandL rl, double[] bfIn, double[] bfNeul1e) {
		slidingWnd(nsent, param.optm_window, rl).forEach(cont -> {
			if (param.optm_cbw)
				cbw(cont, rl, bfIn, bfNeul1e);
			else
				skg(cont, rl, bfNeul1e);
		});
	}

	private void skg(EntryPair<NodeWord, List<NodeWord>> cont, RandL rl, double[] neul1e) {
		cont.value.forEach(tar -> {
			Arrays.fill(neul1e, 0.0);
			ngSamp(tar, cont.key.neuIn, neul1e, rl);
			add(cont.key.neuIn, neul1e);
		});
	}

	private void cbw(EntryPair<NodeWord, List<NodeWord>> cont, RandL rl, double[] bfIn, double[] neul1e) {
		Arrays.fill(bfIn, 0.0);
		Arrays.fill(neul1e, 0.0);
		if (cont.value.size() > 0) {
			cont.value.stream().forEach(src -> add(bfIn, src.neuIn));
			div(bfIn, cont.value.size());
			ngSamp(cont.key, bfIn, neul1e, rl);
			cont.value.stream().forEach(src -> add(src.neuIn, neul1e));
		}
	}

	private void ngSamp(NodeWord tar, double[] in, double[] neul1e, RandL rl) {
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
				if (rtar == tar)
					continue;
				out = rtar.neuOut;
			}
			double f = exp(dot(in, out));
			double g = (label - f) * alpha;
			dxpay(neul1e, out, g);
			dxpay(out, in, g);
		}
	}

	public void train(Iterable<Document> docs) throws InterruptedException, ExecutionException {
		alpha = param.optm_initAlpha;
		preprocess(docs);
		gradientDecend(docs);
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

	public LearnerWordEmbedding(Word2VecParam param) {
		this.param = param;
	}
}
