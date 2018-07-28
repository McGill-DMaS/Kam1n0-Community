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
package ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.annotation.Nonnull;

/**
 * Returns information about the build.
 *
 * @author shevek
 */
public class BuildMetadata {

	public static final String RESOURCE = "/META-INF/jcpp.properties";
	private static BuildMetadata INSTANCE;

	/**
	 * @throws RuntimeException
	 *             if the properties file cannot be found on the classpath.
	 */
	@Nonnull
	public static synchronized BuildMetadata getInstance() {
		try {
			if (INSTANCE == null)
				INSTANCE = new BuildMetadata();
			return INSTANCE;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private final Properties properties = new Properties();

	private BuildMetadata() throws IOException {
		URL url = BuildMetadata.class.getResource(RESOURCE);
		InputStream in = url.openStream();
		try {
			properties.load(in);
		} finally {
			in.close();
		}
	}

	@Nonnull
	public Map<? extends String, ? extends String> asMap() {
		Map<String, String> out = new HashMap<String, String>();
		for (Map.Entry<Object, Object> e : properties.entrySet())
			out.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
		return out;
	}

	// @Nonnull
	// public com.github.zafarkhaja.semver.Version getVersion() {
	// return
	// com.github.zafarkhaja.semver.Version.valueOf(properties.getProperty("Implementation-Version"));
	// }

	@Nonnull
	public Date getBuildDate() throws ParseException {
		// Build-Date=2015-01-01_10:09:09
		String text = properties.getProperty("Build-Date");
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd_HH:mm:ss");
		return format.parse(text);
	}

	public String getChangeId() {
		return properties.getProperty("Change");
	}
}
