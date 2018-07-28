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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Date;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.ArchitectureRepresentation;
import ca.mcgill.sis.dmas.res.KamResourceLoader;

public class Environment {

	private static Logger logger = LoggerFactory.getLogger(Environment.class);
	private static LoggerContext context;

	public static String VERSION = Environment.class.getPackage().getImplementationVersion() == null ? "IDE-Developing"
			: Environment.class.getPackage().getImplementationVersion();

	public static String getUserTmpDir(String user) {
		String path = DmasApplication.applyTmpContext(user) + "/";
		new File(path).mkdirs();
		return path;
	}

	public static String getPlatformTmpDir(String subfolder) {
		String path = DmasApplication.applyTmpContext("km") + "/" + subfolder;
		new File(path).mkdirs();
		return path;
	}

	public static String getAppFolder(long app) {
		String path = DmasApplication.applyDataContext("ApplicationFiles") + '/' + Long.toString(app) + '/';
		new File(path).mkdirs();
		return new File(path).getAbsolutePath();
	}

	public static String getUserFolder(String userName) {
		String key = DigestUtils.sha1Hex(userName);
		String path = DmasApplication.applyDataContext("UserFiles") + '/' + key + '/';
		new File(path).mkdirs();
		return new File(path).getAbsolutePath();
	}

	public static GlobalProperties configuration;

	public static String getVersion() {
		return VERSION + " updated at " + (new Date((new File(KamResourceLoader.jPath_file)).lastModified()));
	}

	public static enum KamMode {
		server, cli
	}

	public static void init(KamMode mode, String... otherEnvironmentVariables) {
		try {
			if (context != null)
				Configurator.shutdown(context);
			LogbackConfig.detachAllandLogToConsole();
		} catch (Exception e) {
			logger.error("Failed to load the logging configuration file for this repository.");
		}

		logger.info("Initializing environment.. Version {}", getVersion());
		GlobalProperties.load();
		int vlen = otherEnvironmentVariables.length;
		if (vlen % 2 != 0)
			logger.warn(
					"The given additional environment variables {} to be set is not correctly formated. Get odd number of elements.",
					Arrays.toString(otherEnvironmentVariables));
		for (int i = 0; i < vlen && i+1 < vlen; i += 2) {
			String key = otherEnvironmentVariables[i];
			String val = otherEnvironmentVariables[i + 1];
			if (key.trim().length() > 0)
				System.setProperty(key, val);
		}

		String PATH_WORKING;
		switch (mode) {
		case server: {
			PATH_WORKING = System.getProperty("kam1n0.data.path", System.getProperty("user.dir"));
			if (!new File(PATH_WORKING).exists())
				new File(PATH_WORKING).mkdirs();
			DmasApplication.contextualize(PATH_WORKING, false, false);
			break;
		}
		case cli: {
			PATH_WORKING = System.getProperty("user.dir");
			DmasApplication.contextualize(PATH_WORKING, false, true);
			break;
		}
		default:
			logger.error("Unsupported mode {}", mode);
			break;
		}

	}

	public static void init() {
		init(KamMode.cli);
	}

}
