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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.DmasApplication;

public class LinesSet implements Iterable<Lines> {

	private static Logger logger = LoggerFactory.getLogger(LinesSet.class);
	private boolean fullyCached = false;

	File[] files;

	public LinesSet(String folderName, boolean fullyCached) {
		folderName = DmasApplication.applyDataContext(folderName);
		File dir = new File(folderName);
		File[] lfiles = dir.listFiles();
		List<File> flfiles = new ArrayList<>();
		for (File file : lfiles) {
			if (file.isFile())
				flfiles.add(file);
		}
		files = flfiles.toArray(new File[flfiles.size()]);
		this.fullyCached = fullyCached;
	}

	@Override
	public Iterator<Lines> iterator() {
		return new LinesIterator();
	}

	public class LinesIterator implements Iterator<Lines> {

		int index = 0;

		@Override
		public boolean hasNext() {
			if (index < files.length)
				return true;
			else
				return false;
		}

		@Override
		public Lines next() {
			File file = files[index];
			index++;
			Lines lines;
			try {
				if (!fullyCached)
					lines = new LinesOnDisk(file.getAbsolutePath());
				else
					lines = new LinesOnRAM(file.getAbsolutePath());
			} catch (IOException e) {
				logger.error("Failed to creat lines.", e);
				return null;
			}
			return lines;
		}

		@Override
		public void remove() {
			logger.error("This set does not support removing entry");
		}

	}

}
