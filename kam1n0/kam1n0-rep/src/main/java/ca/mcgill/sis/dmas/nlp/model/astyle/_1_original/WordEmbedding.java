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

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.function.Function;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import static ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities.*;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.heap.Ranker;
import ca.mcgill.sis.dmas.io.collection.heap.HeapEntry;

public class WordEmbedding implements Serializable {
	private static final long serialVersionUID = 7552873669772683519L;
	private static Logger logger = LoggerFactory.getLogger(WordEmbedding.class);

	public List<EntryPair<String, double[]>> vocabL = null;
	public String param = StringResources.STR_EMPTY;
	public int vecDim = 0;

	public transient HashMap<String, double[]> table = null;

	public WordEmbedding generateTable(int topK) {
		return this.generateTable(topK, null);
	}

	public synchronized WordEmbedding generateTable(int topK, Predicate<String> filter) {
		table = null;
		table = new HashMap<>();
		if (topK < 0)
			topK = vocabL.size();

		for (int i = 0; i < vocabL.size(); ++i) {
			String key = vocabL.get(i).key;
			if (i == 0 || filter == null || filter.test(key)) {
				double[] vec = vocabL.get(i).value.clone();
				normalize(vec);
				table.put(vocabL.get(i).key, vec);
			}
			if (table.size() > topK)
				break;
		}

		return this;

	}

	private static class DataStructForWeb {
		public List<double[]> vecs = new ArrayList<>();
		public List<String> lbls = new ArrayList<>();
		public List<String> grps = new ArrayList<>();
	}

	public synchronized void saveCurrentTableForVisualization(String file, Function<String, String> groupMap) {
		try {
			DataStructForWeb data = new DataStructForWeb();
			this.table.entrySet().stream().filter(ent -> !ent.getKey().equalsIgnoreCase("</s>")).forEach(ent -> {
				data.vecs.add(ent.getValue());
				data.lbls.add(ent.getKey());
				if (groupMap != null)
					data.grps.add(groupMap.apply(ent.getKey()));
			});
			(new ObjectMapper()).writeValue(new File(file), data);
		} catch (Exception e) {
			logger.error("Failed to save data to " + file, e);
		}
	}

	public Ranker<String> analogy(String w0, String w1, String w2, int topK) {
		double[] wv0 = table.get(w0.trim().toLowerCase());
		double[] wv1 = table.get(w1.trim().toLowerCase());
		double[] wv2 = table.get(w2.trim().toLowerCase());
		if (wv1 == null || wv2 == null || wv0 == null)
			return null;
		double[] wv = new double[wv0.length];
		for (int i = 0; i < wv.length; i++)
			wv[i] = wv1[i] - wv0[i] + wv2[i];
		return lookup(wv, topK, w0, w1, w2);
	}

	public Ranker<String> lookup(double[] vec, int topK, String... excludes) {
		topK = table.size() < topK ? table.size() : topK;
		Ranker<String> result = new Ranker<>(topK);
		table.forEach((k, v) -> {
			for (String tkn : excludes)
				if (tkn.equals(k))
					return;
			double dist = dot(v, vec);
			result.push(dist, k);
		});
		return result;
	}

	/**
	 * 
	 * @param questionsFile
	 * @return an three-element array of double[], corresponding to semantic
	 *         accuracy, syntactic accuracy, and overall accuracy
	 */
	public double[] computeAccuracy(String questionsFile) {
		int syn_correct = 0, syn_total = 0, sem_correct = 0, sem_total = 0;

		Lines questions;
		try {
			questions = Lines.fromFile(questionsFile);
		} catch (Exception e) {
			logger.error("Failed to open question file.", e);
			return null;
		}
		int classCount = 0;
		int problemCount = 0;
		String prevClass = StringResources.STR_EMPTY;
		boolean isSynQuestion = false;
		for (String question : questions) {
			if (question.startsWith(":")) {
				classCount++;
				if (question.contains("gram"))
					isSynQuestion = true;
				if (classCount != 1) {
					logger.info("Class {}", prevClass);
					double synacc = syn_correct * 100.0 / syn_total;
					double semacc = sem_correct * 100.0 / sem_total;
					double totalacc = (syn_correct + sem_correct) * 100.0 / (syn_total + sem_total);
					logger.info("Eval: syntatic {}% {}/{}, sematic {}% {}/{}, total {}% {}/{}",
							StringResources.FORMAT_2R4D.format(synacc), syn_correct, syn_total,
							StringResources.FORMAT_2R4D.format(semacc), sem_correct, sem_total,
							StringResources.FORMAT_2R4D.format(totalacc), (syn_correct + sem_correct),
							(sem_total + syn_total));
				}
				prevClass = question;
				continue;
			}
			problemCount++;
			String[] words = question.toLowerCase().split("\\s+");
			if (words.length != 4) {
				logger.error("Invalid question: {}", question);
				continue;
			}
			if (!table.containsKey(words[3].trim().toLowerCase()))
				continue;
			Ranker<String> set = analogy(words[0], words[1], words[2], 1);
			if (set == null || set.size() < 1)
				continue;
			HeapEntry<String> answer = set.pollFirst();
			if (answer.value.equals(words[3])) {
				if (isSynQuestion)
					syn_correct++;
				else
					sem_correct++;
			}
			if (isSynQuestion)
				syn_total++;
			else {
				sem_total++;
			}
		}
		double synacc = syn_correct * 1.0 / syn_total;
		double semacc = sem_correct * 1.0 / sem_total;
		double totalacc = (syn_correct + sem_correct) * 1.0 / (syn_total + sem_total);
		logger.info("Finished Eval: syntatic {}% {}/{}, semantic {}% {}/{}, total {}% {}/{}",
				StringResources.FORMAT_2R4D.format(synacc * 100), syn_correct, syn_total,
				StringResources.FORMAT_2R4D.format(semacc * 100), sem_correct, sem_total,
				StringResources.FORMAT_2R4D.format(totalacc * 100), (syn_correct + sem_correct),
				(sem_total + syn_total));
		logger.info("Coverage: {}% {}/{}", (sem_total + syn_total) * 100.0 / problemCount, (sem_total + syn_total),
				problemCount);
		return new double[] { synacc, semacc, totalacc };
	}

	public void runConsole(int topK) {
		logger.info("Input words seperated by space. Enter 'EXIT' to exit console");
		Scanner input = new Scanner(System.in);
		String line = null;
		while (!(line = input.nextLine()).equals("EXIT")) {
			String[] words = line.toLowerCase().trim().split("\\s+");
			double[] vec = new double[table.get("</s>").length];
			Arrays.stream(words).map(w -> table.get(w)).filter(notNull).forEach(wv -> add(vec, wv));
			if (areZeros(vec)) {
				logger.info("Empty result");
				continue;
			}
			Ranker<String> set = lookup(vec, topK, words);
			for (HeapEntry<String> ent : set) {
				String name = String.format("%-15s", ent.value);
				System.out.println(name + "\t" + ent.score);
			}
		}
		input.close();
		logger.info("Exiting embedding console.");
	}

	public void save(File file) throws IOException {
		ObjectOutputStream oStream = new ObjectOutputStream(new FileOutputStream(file));
		oStream.writeObject(this);
		oStream.close();
	}

	public static WordEmbedding load(File file) throws ClassNotFoundException, IOException {
		ObjectInputStream iStream = new ObjectInputStream(new FileInputStream(file));
		Object embedding = iStream.readObject();
		iStream.close();
		return (WordEmbedding) embedding;
	}

	public static WordEmbedding loadGoogleModel(File file) throws IOException {
		DataInputStream dis = null;
		BufferedInputStream bis = null;
		float vector = 0;
		WordEmbedding embd = new WordEmbedding();
		embd.param = "Google-Model-" + file.getName();
		try {
			bis = new BufferedInputStream(new FileInputStream(file));
			dis = new DataInputStream(bis);
			int words = Integer.parseInt(readString(dis));
			embd.vocabL = new ArrayList<EntryPair<String, double[]>>(words);
			int layerSize = Integer.parseInt(readString(dis));
			String word;
			double[] vectors = null;
			for (int i = 0; i < words; i++) {
				word = readString(dis);
				vectors = new double[layerSize];
				for (int j = 0; j < layerSize; j++) {
					vector = readFloat(dis);
					vectors[j] = (float) vector;
				}
				embd.vocabL.add(new EntryPair<>(word, vectors));
				dis.read();
			}
		} finally {
			bis.close();
			dis.close();
		}
		return embd;
	}

	private static float readFloat(InputStream is) throws IOException {
		byte[] bytes = new byte[4];
		is.read(bytes);
		return getFloat(bytes);
	}

	private static float getFloat(byte[] b) {
		int accum = 0;
		accum = accum | (b[0] & 0xff) << 0;
		accum = accum | (b[1] & 0xff) << 8;
		accum = accum | (b[2] & 0xff) << 16;
		accum = accum | (b[3] & 0xff) << 24;
		return Float.intBitsToFloat(accum);
	}

	private static final int MAX_SIZE = 100;

	private static String readString(DataInputStream dis) throws IOException {
		byte[] bytes = new byte[MAX_SIZE];
		byte b = dis.readByte();
		int i = -1;
		StringBuilder sb = new StringBuilder();
		while (b != 32 && b != 10) {
			i++;
			bytes[i] = b;
			b = dis.readByte();
			if (i == 49) {
				sb.append(new String(bytes));
				i = -1;
				bytes = new byte[MAX_SIZE];
			}
		}
		sb.append(new String(bytes, 0, i + 1));
		return sb.toString();
	}
}
