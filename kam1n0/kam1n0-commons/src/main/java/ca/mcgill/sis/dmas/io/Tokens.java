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

import java.nio.charset.Charset;

public abstract class Tokens implements Iterable<String> {

	
	public static Tokens fromFile(String fileName) throws Exception{
		return new TokensOnDisk(fileName);
	}
	
	public static Tokens fromFile(String fileName, String deliminator) throws Exception{
		return new TokensOnDisk(fileName, deliminator);
	}
	
	
	public static Tokens fromGzip(String fileName) throws Exception{
		return new TokensOnGzip(fileName);
	}
	
	public static Tokens fromGzip(String fileName, String deliminator, Charset charset) throws Exception{
		return new TokensOnGzip(fileName, deliminator, charset);
	}
	
	public abstract Lines groupIntoLines(int lineLength);
}
