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
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;
import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static ca.mcgill.sis.dmas.env.DmasApplication.applyDataContext;
import ca.mcgill.sis.dmas.env.StringResources;

public class TokensOnDisk extends Tokens {
	private Logger logger = LoggerFactory.getLogger(TokensOnDisk.class);

	
	private String deliminator_;
	private String fileName_;

	public TokensOnDisk(String file, String deliminater) throws IOException {
		file = applyDataContext(file);
		deliminator_ = deliminater;
		fileName_ = file;
	}

	public TokensOnDisk(String file) throws IOException {
		file = applyDataContext(file);
		deliminator_ = STR_SPACE_DELIMINATER;
		fileName_ = file;
	}


	public static final String STR_SPACE_DELIMINATER = "\\p{javaWhitespace}+";

	@Override
	public Iterator<String> iterator() {
		return new TokenIterator();
	}
	
	public class TokenIterator implements Iterator<String> {

		String line;
		volatile boolean closed = false;
		private Scanner scanner = null;
		
		public TokenIterator(){
			BufferedReader bReader;
			try {
				bReader = new BufferedReader(new FileReader(fileName_));
				scanner = new Scanner(bReader);
				scanner.useDelimiter(deliminator_);
			} catch (FileNotFoundException e) {
				logger.error("Failed to open file", e);
			}
			
		}
		

		@Override
		public boolean hasNext() {
			if (closed == true)
				return false;
			if (scanner.hasNext())
				return true;
			else {
				try {
					scanner.close();
				} catch (Exception e1) {
				}
				closed = true;
				return false;
			}
		}

		@Override
		public String next() {
			return scanner.next();
		}

		@Override
		public void remove() {
			logger.error("Unable to remove element. This is an immutable iterator.");
		}

	}

	public class LinesFromTokens extends Lines {
		private TokensOnDisk tokensInFile = null;
		private int group = 15;

		public LinesFromTokens(TokensOnDisk tokens, int groupSize) {
			group = groupSize;
			tokensInFile = tokens;
		}

		@Override
		public Iterator<String> iterator() {
			return new LineIterator();
		}

		public class LineIterator implements Iterator<String> {

			public LineIterator() {
				if (tokensInFile != null) {
					tokens = tokensInFile.iterator();
				}
			}

			Iterator<String> tokens = null;

			@Override
			public boolean hasNext() {
				return tokens.hasNext();
			}

			@Override
			public String next() {
				StringBuilder lineBuilder = new StringBuilder();
				int count = 0;
				while (count < group && tokens.hasNext()) {
					lineBuilder.append(tokens.next()).append(
							StringResources.STR_TOKENBREAK);
					count++;
				}
				return lineBuilder.toString();
			}

			@Override
			public void remove() {
				logger.error("Unable to remove element. This is an immutable iterator.");
			}

		}
	}

	public Lines groupIntoLines(int groupSize){
		return new LinesFromTokens(this, groupSize);
	}
	
}
