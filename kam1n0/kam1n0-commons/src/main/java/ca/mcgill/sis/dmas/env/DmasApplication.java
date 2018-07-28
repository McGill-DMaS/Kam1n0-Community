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
import java.io.IOException;
import java.nio.file.Files;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.io.file.DmasFileOperations;

public class DmasApplication {
	public static String STR_DATA_PATH = "";
	public static String STR_DATA_PATH_TMP = "tmp/";

	private static Logger logger = LoggerFactory.getLogger(DmasApplication.class);

	public static String applyDataContext(String filePath) {
		File file = new File(filePath);
		if (file.isAbsolute())
			return filePath;
		else
			return STR_DATA_PATH + filePath;
	}

	public static void cleanTmpFolder() {
		try {
			File file = new File(STR_DATA_PATH_TMP);
			DmasFileOperations.deleteRecursively(file.getAbsolutePath());
			file.mkdir();
		} catch (Exception e) {
			logger.info("Failed to clean tmp dir.", e);
		}
	}

	public static String applyTmpContext(String filePath) {
		File file = new File(filePath);
		if (file.isAbsolute())
			return filePath;
		else
			return STR_DATA_PATH_TMP + "/" + filePath;
	}

	public static void contextualize(String dataPath) {
		File file = new File(dataPath);
		if (file.isDirectory()) {
			STR_DATA_PATH = dataPath + "/";
			STR_DATA_PATH_TMP = STR_DATA_PATH + "/tmp/";
		}
		if ((new File(STR_DATA_PATH_TMP).exists())) {
			try {
				DmasFileOperations.deleteRecursively(STR_DATA_PATH_TMP);
			} catch (Exception e) {
				logger.error("Failed to delete existing tmp folder: " + STR_DATA_PATH_TMP, e);
			}
		}
		(new File(STR_DATA_PATH_TMP)).mkdirs();
	}

	public static void contextualize(String dataPath, boolean deleteTmpFolder, boolean useSystemTmp) {
		File file = new File(dataPath);
		if (file.isDirectory()) {
			STR_DATA_PATH = dataPath + "/";
			if (!useSystemTmp)
				STR_DATA_PATH_TMP = STR_DATA_PATH + "/tmp/";
			else
				try {
					STR_DATA_PATH_TMP = Files.createTempDirectory("kam1n0-tmp").toFile().getAbsolutePath();
				} catch (IOException e) {
					logger.error(
							"Failed to create system tmp folder for kam1n0. Creating a tmp folder in working data dir.");
					STR_DATA_PATH_TMP = STR_DATA_PATH + "/tmp/";
				}
		}
		if (deleteTmpFolder && (new File(STR_DATA_PATH_TMP).exists())) {
			try {
				DmasFileOperations.deleteRecursively(STR_DATA_PATH_TMP);
			} catch (Exception e) {
				logger.error("Failed to delete existing tmp folder: " + STR_DATA_PATH_TMP, e);
			}
		}
		(new File(STR_DATA_PATH_TMP)).mkdirs();
	}

	public static void contextualize(String dataPath, String tmpPath, boolean deleteTmpFolder) {
		File file = new File(dataPath);
		if (file.isDirectory()) {
			STR_DATA_PATH = dataPath + "/";
			STR_DATA_PATH_TMP = tmpPath + "/Kam1n0_tmp/";
		}
		if (deleteTmpFolder && (new File(STR_DATA_PATH_TMP).exists())) {
			try {
				DmasFileOperations.deleteRecursively(STR_DATA_PATH_TMP);
			} catch (Exception e) {
				logger.error("Failed to delete existing tmp folder: " + STR_DATA_PATH_TMP, e);
			}
		}
		(new File(STR_DATA_PATH_TMP)).mkdirs();
	}

	public static File createTmpFile(String name) {
		File file = new File(STR_DATA_PATH_TMP + name);
		try {
			file.createNewFile();
			return file;
		} catch (IOException e) {
			return null;
		}
	}

	public static File createTmpFolder(String name) {
		File file = new File(STR_DATA_PATH_TMP + name);
		file.mkdir();
		return file;
	}

	public static String removeFileExtension(String file) {
		return file.substring(0, file.lastIndexOf('.'));
	}

}
