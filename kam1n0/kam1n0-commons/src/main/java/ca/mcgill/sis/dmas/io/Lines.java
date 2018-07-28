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
package ca.mcgill.sis.dmas.io;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.StringResources;

import com.google.common.base.Charsets;
import com.google.common.collect.Iterables;

public abstract class Lines implements Iterable<String> {

	private static Logger logger = LoggerFactory.getLogger(Lines.class);

	public static Lines fromFileFullyCached(String file) throws Exception {
		return new LinesOnRAM(file);
	}

	public static Lines fromFileFullyCached(String file, Charset charset) throws Exception {
		return new LinesOnRAM(file, charset);
	}

	public static Lines fromFile(String file) throws Exception {
		return new LinesOnDisk(file);
	}

	public static Lines fromFile(String file, Charset charset) throws Exception {
		return new LinesOnDisk(file, charset);
	}

	public static Lines fromFileGzip(String file) throws Exception {
		return new LinesOnGzip(file, Charsets.UTF_8);
	}

	public static Lines fromFileGzip(String file, Charset encoding) throws Exception {
		return new LinesOnGzip(file, encoding);
	}

	public static Lines fromTokens(Tokens tif, int lineLength) throws Exception {
		return tif.groupIntoLines(lineLength);
	}

	public static Lines fromFolder(String folder, boolean fullyCached) {
		return new LinesOnLinesSet(new LinesSet(folder, fullyCached));
	}

	public static Lines from(String... lines) {
		return new LinesFromArray(lines);
	}

	public static Lines from(List<String> lines) {
		return new LinesFromArray(lines);
	}

	private static class LinesFromArray extends Lines {

		String[] array;

		public LinesFromArray(String[] array) {
			this.array = array;
		}

		public LinesFromArray(List<String> array) {
			this.array = array.toArray(new String[array.size()]);
		}

		@Override
		public Iterator<String> iterator() {
			return Arrays.asList(array).iterator();
		}

	}

	public static Lines mergeToMultiLines(Lines... linesList) {
		return new MergedLines(linesList);
	}

	public static String mergeToSingleLine(Lines... linesList) {
		StringBuilder sBuilder = new StringBuilder();
		for (Lines lines : linesList) {
			for (String line : lines) {
				sBuilder.append(line).append(StringResources.STR_TOKENBREAK);
			}
		}
		return sBuilder.toString();
	}

	public static String readAll(String file, Charset charset, boolean isGzip) throws Exception {
		file = DmasApplication.applyDataContext(file);
		if (!isGzip)
			return mergeToSingleLine(Lines.fromFile(file, charset));
		else {
			return mergeToSingleLine(Lines.fromFileGzip(file, charset));
		}
	}

	public static ArrayList<String> readAllAsArray(String file, Charset charset, boolean isGizp) throws Exception {
		file = DmasApplication.applyDataContext(file);
		Lines lines;
		if (!isGizp)
			lines = Lines.fromFile(file, charset);
		else {
			lines = Lines.fromFileGzip(file, charset);
		}
		ArrayList<String> rList = new ArrayList<>();
		for (String string : lines) {
			rList.add(string);
		}
		return rList;
	}

	/**
	 * assume that all line number of file starts from 0
	 * 
	 * @param lines
	 * @param start_included
	 * @param end_excluded
	 * @return
	 */
	public static ArrayList<String> selectAsList(Lines lines, int start_included, int end_excluded) {
		ArrayList<String> rlines = new ArrayList<>();
		Iterable<String> ite_select = Iterables.limit(Iterables.skip(lines, start_included),
				end_excluded - start_included);
		for (String string : ite_select) {
			rlines.add(string);
		}
		return rlines;
	}

	/**
	 * assume that all line number of file starts from 0
	 * 
	 * @param lines
	 * @param start_included
	 * @param end_excluded
	 * @return
	 */
	public static String selectAsString(Lines lines, int start_included, int end_excluded) {
		StringBuilder sBuilder = new StringBuilder();
		Iterable<String> ite_select = Iterables.limit(Iterables.skip(lines, start_included),
				end_excluded - start_included);
		for (String string : ite_select) {
			sBuilder.append(string).append(StringResources.STR_LINEBREAK);
		}
		return sBuilder.toString();
	}

	/**
	 * assume that all line number of file starts from 0
	 * 
	 * @param lines
	 * @param start_included
	 * @param end_excluded
	 * @return
	 */
	public static Lines selectAsLines(Lines lines, int start_included, int end_excluded) {
		ArrayList<String> rlines = new ArrayList<>();
		Iterable<String> ite_select = Iterables.limit(Iterables.skip(lines, start_included),
				end_excluded - start_included);
		for (String string : ite_select) {
			rlines.add(string);
		}
		return Lines.from(rlines.toArray(new String[rlines.size()]));
	}

	public static LineSequenceWriter getLineWriter(String fileName, boolean compressed) throws Exception {
		return new LineSequenceWriter(fileName, compressed);
	}

	public static boolean flushToFile(Lines lines, String fileToSave) {
		fileToSave = DmasApplication.applyDataContext(fileToSave);

		File file = new File(fileToSave);
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(file));
			for (String string : lines) {
				bw.write(string);
				bw.newLine();
			}
			bw.flush();
			bw.close();
		} catch (Exception e) {
			logger.error("Failed to save into file.", e);
			return false;
		}
		return true;
	}

	public static boolean flushToFile(String str, String fileToSave, Charset charset) {
		fileToSave = DmasApplication.applyDataContext(fileToSave);

		File file = new File(fileToSave);
		try {
			BufferedWriter bw = new BufferedWriter(new FileWriter(file));
			bw.write(str);
			bw.flush();
			bw.close();
		} catch (Exception e) {
			logger.error("Failed to save into file.", e);
			return false;
		}
		return true;
	}

	public static boolean flushToFile(Lines lines, String fileToSave, Charset charset) {
		fileToSave = DmasApplication.applyDataContext(fileToSave);

		File file = new File(fileToSave);
		try {
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), charset));
			for (String string : lines) {
				bw.write(string);
				bw.newLine();
			}
			bw.flush();
			bw.close();
		} catch (Exception e) {
			logger.error("Failed to save into file.", e);
			return false;
		}
		return true;
	}

	public static boolean flushToGzip(Lines lines, String fileToSave) {
		fileToSave = DmasApplication.applyDataContext(fileToSave);
		File file = new File(fileToSave);
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(file);
			GZIPOutputStream outputStream = new GZIPOutputStream(fileOutputStream);
			Writer writer = new OutputStreamWriter(outputStream, Charsets.UTF_8);
			BufferedWriter bw = new BufferedWriter(writer);

			for (String string : lines) {
				bw.write(string);
				bw.newLine();
			}
			bw.flush();
			bw.close();

		} catch (Exception e) {
			logger.error("Failed to save into file.", e);
			return false;
		}
		return true;
	}

	public static boolean flushToGzip(Lines lines, String fileToSave, Charset charset) {
		fileToSave = DmasApplication.applyDataContext(fileToSave);
		File file = new File(fileToSave);
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(file);
			GZIPOutputStream outputStream = new GZIPOutputStream(fileOutputStream);
			Writer writer = new OutputStreamWriter(outputStream, charset);
			BufferedWriter bw = new BufferedWriter(writer);

			for (String string : lines) {
				bw.write(string);
				bw.newLine();
			}
			bw.flush();
			bw.close();

		} catch (Exception e) {
			logger.error("Failed to save into file.", e);
			return false;
		}
		return true;
	}

	public void print() {
		for (String line : this) {
			System.out.println(line);
		}
	}

	public static Lines filter(Lines lines, String regex) {
		return new LinesFiltered(lines, regex, false);
	}

	public static Lines filterSkipEmpty(Lines lines, String regex) {
		return new LinesFiltered(lines, regex, true);
	}

	public static class MergedLines extends Lines {

		public MergedLines(Lines... listOfLines) {
			array = listOfLines;
		}

		Lines[] array;

		@Override
		public Iterator<String> iterator() {
			return Iterables.concat(Arrays.asList(array)).iterator();
		}

	}

	public static void flushToFile(Iterable<? extends Object> vals, String file) throws Exception {
		LineSequenceWriter writer = getLineWriter(file, false);
		for (Object val : vals)
			writer.writeLine(val.toString());
		writer.close();
	}

	public static void main(String[] args) {

	}
}
