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

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.nlp.model.astyle.MathUtilities;

public class WordEmbeddingChecker {

	private static Logger logger = LoggerFactory.getLogger(WordEmbeddingChecker.class);

	public static boolean checkVocab(WordEmbedding ebd1, WordEmbedding ebd2) {
		if (ebd1.vocabL.size() != ebd2.vocabL.size())
			return false;
		logger.info("{} vs {}", ebd1.vocabL.size(), ebd2.vocabL.size());
		// check vocab order & word
		for (int i = 0; i < ebd1.vocabL.size(); ++i)
			if (!ebd1.vocabL.get(i).key.equals(ebd2.vocabL.get(i).key))
				return false;
		return true;
	}

	public static void lineCompare(String file1, String file2) throws Exception {
		Iterator<String> l1 = Lines.fromFileFullyCached(file1).iterator();
		Iterator<String> l2 = Lines.fromFileFullyCached(file2).iterator();

		int lineNum = 0;
		while (l1.hasNext()) {
			String line1 = l1.next();
			lineNum++;
			if (!l2.hasNext())
				break;
			String line2 = l2.next();
			if (!line2.trim().equals(line1.trim())) {
				System.out.println(lineNum + " :");
				System.out.println(line1);
				System.out.println(line2);
				System.out.println("");
				continue;
			}
		}

		System.out.println(lineNum);

	}

	public static List<Integer> checkVocabEmbed(WordEmbedding ebd1, WordEmbedding ebd2) {

		// really need to know the error? or simple a counter?
		// stay with the counter at this moment.

		List<Integer> errors = IntStream.range(0, ebd1.vocabL.size()).mapToObj(ind -> {
			EntryPair<String, double[]> p1 = ebd1.vocabL.get(ind);
			EntryPair<String, double[]> p2 = ebd2.vocabL.get(ind);
			if (!p1.key.equals(p2.key))
				return new Integer(ind);
			if (p1.value.length != p2.value.length)
				return new Integer(ind);
			boolean same = true;
			for (int i = 0; i < p1.value.length; ++i) {
				double val1 = round(p1.value[i], 6);
				double val2 = round(p2.value[i], 6);
				if (val1 != val2) {
					same = false;
					break;
				}
			}
			if (!same)
				return new Integer(ind);
			return null;
		}).filter(MathUtilities.notNull).collect(Collectors.toList());
		return errors;
	}

	public static double round(double value, int places) {
		if (places < 0)
			throw new IllegalArgumentException();

		BigDecimal bd = new BigDecimal(value);
		bd = bd.setScale(places, RoundingMode.HALF_UP);
		return bd.doubleValue();
	}

	public static void main(String[] args) throws Exception, IOException {
		WordEmbedding ebdo = WordEmbedding.load(new File("E:\\authorship\\text8\\vectors.init.dmas.bin"));
		WordEmbedding ebdg = WordEmbedding.loadGoogleModel(new File("E:\\authorship\\text8\\vectors.init.google.bin"));

		logger.info(Boolean.toString(checkVocab(ebdo, ebdg)));
		logger.info(Integer.toString(checkVocabEmbed(ebdo, ebdg).size()));

		// lineCompare("E:\\authorship\\text8\\debug.dmas.txt","E:\\authorship\\text8\\debug.google.txt");
	}

	public static void test(String[] args) {
		WordEmbedding ebd1 = new WordEmbedding();
		WordEmbedding ebd2 = new WordEmbedding();

		// check vocab
		ebd1.vocabL = Arrays.asList(new EntryPair<>("a", new double[3]), new EntryPair<>("a", new double[3]),
				new EntryPair<>("a", new double[3]));

		ebd2.vocabL = Arrays.asList(new EntryPair<>("a", new double[3]), new EntryPair<>("a", new double[3]));

		logger.info(Boolean.toString(checkVocab(ebd1, ebd2))); // false

		ebd1.vocabL = Arrays.asList(new EntryPair<>("a", new double[3]), new EntryPair<>("a", new double[3]),
				new EntryPair<>("a", new double[3]));

		ebd2.vocabL = Arrays.asList(new EntryPair<>("a", new double[3]), new EntryPair<>("a", new double[3]),
				new EntryPair<>("a", new double[3]));

		logger.info(Boolean.toString(checkVocab(ebd1, ebd2))); // true

		ebd1.vocabL = Arrays.asList(new EntryPair<>("a", new double[3]), new EntryPair<>("a", new double[3]),
				new EntryPair<>("a", new double[3]));

		ebd2.vocabL = Arrays.asList(new EntryPair<>("a", new double[3]), new EntryPair<>("c", new double[3]),
				new EntryPair<>("a", new double[3]));

		logger.info(Boolean.toString(checkVocab(ebd1, ebd2))); // false

		ebd1.vocabL = Arrays.asList(new EntryPair<>("a", new double[] { 1f, 2f, 3f }),
				new EntryPair<>("b", new double[] { 1f, 2f, 3f }), new EntryPair<>("c", new double[] { 1f, 2f, 3f }));

		ebd2.vocabL = Arrays.asList(new EntryPair<>("a", new double[] { 1f, 2f, 3f }),
				new EntryPair<>("b", new double[] { 1f, 2f, 3f }), new EntryPair<>("c", new double[] { 1f, 2f, 3f }));

		logger.info(checkVocabEmbed(ebd1, ebd2).toString()); // empty

		ebd1.vocabL = Arrays.asList(new EntryPair<>("a", new double[] { 1f, 2f, 3f }),
				new EntryPair<>("d", new double[] { 1f, 2f, 3f }), new EntryPair<>("c", new double[] { 1f, 2f, 3f }));

		ebd2.vocabL = Arrays.asList(new EntryPair<>("a", new double[] { 1f, 2f, 3f }),
				new EntryPair<>("b", new double[] { 1f, 2f, 3f }), new EntryPair<>("c", new double[] { 1f, 2f, 3f }));

		logger.info(checkVocabEmbed(ebd1, ebd2).toString()); // 1

		ebd1.vocabL = Arrays.asList(new EntryPair<>("a", new double[] { 1f, 2f, 3f }),
				new EntryPair<>("d", new double[] { 1f, 2f, 3f }), new EntryPair<>("c", new double[] { 1f, 0f, 3f }));

		ebd2.vocabL = Arrays.asList(new EntryPair<>("a", new double[] { 1f, 2f, 3f }),
				new EntryPair<>("b", new double[] { 1f, 2f, 3f }), new EntryPair<>("c", new double[] { 1f, 2f, 3f }));

		logger.info(checkVocabEmbed(ebd1, ebd2).toString()); // 1,2

		// check pre-processing
		// check single iteration negative sampling (single-threaded)

	}

}
