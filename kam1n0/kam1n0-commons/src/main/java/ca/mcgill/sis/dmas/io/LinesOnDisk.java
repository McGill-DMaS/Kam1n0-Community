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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ca.mcgill.sis.dmas.env.DmasApplication.applyDataContext;

public class LinesOnDisk extends Lines {

	private Logger logger = LoggerFactory.getLogger(LinesOnDisk.class);
	String file_;

	public LinesOnDisk(String file) throws IOException {
		file = applyDataContext(file);
		file_ = file;
	}

	public LinesOnDisk(String file, Charset charset) throws IOException {
		file = applyDataContext(file);
		file_ = file;
		this.encoding = charset;
	}

	Charset encoding = Charset.defaultCharset();

	@Override
	public Iterator<String> iterator() {
		return new LineIterator();
	}

	public class LineIterator implements Iterator<String> {

		private BufferedReader bReader = null;

		public LineIterator() {
			try {
				bReader = new BufferedReader(new InputStreamReader(new FileInputStream(file_), encoding));
			} catch (FileNotFoundException e) {
				logger.error("Failed to open file.", e);
			}
		}

		String line = null;

		volatile boolean closed = false;

		@Override
		public boolean hasNext() {
			if (closed)
				return false;
			if (line != null)
				return true;

			try {
				line = bReader.readLine();
				if (line == null) {
					bReader.close();
					return false;
				} else {
					return true;
				}
			} catch (IOException e) {
				logger.error("Unable to read from file", e);
				try {
					closed = true;
					bReader.close();
				} catch (Exception e1) {
				}
				return false;
			}
		}

		@Override
		public String next() {
			String nextLine = line;
			line = null;
			return nextLine;
		}

		@Override
		public void remove() {
			logger.error("Unable to remove element. This is an immutable iterator.");
		}

	}

}
