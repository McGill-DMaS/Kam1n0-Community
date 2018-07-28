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
package ca.mcgill.sis.dmas.env;

import java.io.File;
import java.net.URL;
import java.util.Iterator;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class GlobalProperties {

	private final static String propertyFile = "kam1n0.properties";
	private static Logger logger = LoggerFactory.getLogger(GlobalProperties.class);

	public static void load() {
		try {
			load(GlobalProperties.class.getClassLoader().getResource(propertyFile));
			File externalized = KamResourceLoader.loadFile(propertyFile);
			if (externalized != null) {
				load(externalized.toURI().toURL());
			}
		} catch (Exception e) {
			logger.error("Failed to read kam1n0 property file.", e);
		}
	}

	private static void load(URL uri) throws Exception {
		if (uri == null)
			return;
		PropertiesConfiguration config = new PropertiesConfiguration(uri);
		config.setDelimiterParsingDisabled(true);
		@SuppressWarnings("unchecked")
		Iterator<String> ite = config.getKeys();
		while (ite.hasNext()) {
			String key = ite.next();
			if (key.trim().length() > 0)
				System.setProperty(key, config.getString(key));
		}
	}

}
