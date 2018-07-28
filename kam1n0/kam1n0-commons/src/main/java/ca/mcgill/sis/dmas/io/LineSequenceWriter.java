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
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.zip.GZIPOutputStream;

import com.google.common.base.Charsets;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.StringResources;

public class LineSequenceWriter {

	BufferedWriter bw;

	private File file;

	public File getFile() {
		return file;
	}

	public LineSequenceWriter(String fileName, boolean compressed) throws Exception {
		fileName = DmasApplication.applyDataContext(fileName);
		file = new File(fileName);
		if (!compressed) {
			bw = new BufferedWriter(new FileWriter(file));
		} else {
			FileOutputStream fileOutputStream = new FileOutputStream(file);
			GZIPOutputStream outputStream = new GZIPOutputStream(fileOutputStream);
			bw = new BufferedWriter(new OutputStreamWriter(outputStream, Charsets.UTF_8));
		}
	}

	public void close() throws Exception {
		bw.close();
	}

	public void writeLine(String line) throws Exception {
		bw.write(line);
		bw.write(StringResources.STR_LINEBREAK);
	}

	public void writeLine(String... tokens) {
		try {
			bw.write(StringResources.JOINER_TOKEN.join(tokens));
			bw.write(StringResources.STR_LINEBREAK);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void writeLineCSV(Object... partsForOneLine) throws Exception {
		bw.write(StringResources.JOINER_TOKEN_CSV.join(partsForOneLine));
		bw.write(StringResources.STR_LINEBREAK);
	}

	public void writeLine(String line, boolean flush) throws Exception {
		bw.write(line);
		if (flush)
			bw.flush();
		bw.write(StringResources.STR_LINEBREAK);
	}

	public <T extends Object> void writeLineNoExcept(T line) {
		try {
			bw.write(line.toString());
			bw.write(StringResources.STR_LINEBREAK);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void writeLineCSV(boolean flush, Object... partsForOneLine) throws Exception {
		bw.write(StringResources.JOINER_TOKEN_CSV.join(partsForOneLine));
		bw.write(StringResources.STR_LINEBREAK);
		if (flush)
			bw.flush();
	}

}
