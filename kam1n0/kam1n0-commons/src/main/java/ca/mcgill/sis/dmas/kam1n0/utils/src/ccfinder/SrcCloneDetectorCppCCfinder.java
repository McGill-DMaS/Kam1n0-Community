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
package ca.mcgill.sis.dmas.kam1n0.utils.src.ccfinder;

import gnu.trove.map.hash.TIntDoubleHashMap;
import gnu.trove.map.hash.TIntObjectHashMap;
import gnu.trove.map.hash.TLongObjectHashMap;

import java.io.File;
import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.Lines;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.io.collection.Pool;
import ca.mcgill.sis.dmas.io.file.DmasFileOperations;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.utils.src.SrcFunction;

public class SrcCloneDetectorCppCCfinder extends SrcCloneDetector {

	private static Logger logger = LoggerFactory.getLogger(SrcCloneDetector.class);

	public final String PATH_CCFINDERX;
	public final String PATH_CCFINDERX_EXE;
	public final String PATH_PYTHON26;

	public int b;
	public int t;

	public final boolean validCCfinder;

	public SrcCloneDetectorCppCCfinder() {
		this(System.getProperty("kam1n0.ccfinder.home", System.getProperty("user.dir")),
				System.getProperty("kam1n0.ccfinder.python26exe", System.getProperty("user.dir") + "/python.exe"),
				Integer.parseInt(System.getProperty("kam1n0.ccfinder.b", "12")),
				Integer.parseInt(System.getProperty("kam1n0.ccfinder.t", "50")));

	}

	public SrcCloneDetectorCppCCfinder(String ccfinderPath, String pythonPathForCCFINDERX, int b, int t) {
		this.b = b;
		this.t = t;
		PATH_PYTHON26 = pythonPathForCCFINDERX;

		PATH_CCFINDERX = ccfinderPath;

		// if (!(new File(PATH_CCFINDERX).exists())) {
		// logger.error("Invalid path.");
		// }

		PATH_CCFINDERX_EXE = PATH_CCFINDERX + "/bin/ccfx.exe";
		if (!(new File(PATH_CCFINDERX_EXE).exists())) {
			// logger.error("ccfx.exe nonexist!");
			this.validCCfinder = false;
			return;
		}

		this.validCCfinder = true;
	}

	Pattern getM = Pattern.compile("[^\\w]");

	public boolean verify(SrcFunction srcFunction) {
		String[] token = StringResources.JOINER_TOKEN.join(srcFunction.content).trim().split(" ");
		if (token.length < 3)
			return false;
		else
			return true;
	}

	@Override
	public boolean detectClones(Iterable<SrcFunction> functions1, Iterable<SrcFunction> functions2) throws Exception {

		File tmpFolderRoot = DmasApplication.createTmpFolder(StringResources.randomString(5));

		File tmpFolder1 = DmasApplication
				.createTmpFolder(tmpFolderRoot.getName() + "/" + StringResources.randomString(5));
		File tmpFolder2 = DmasApplication
				.createTmpFolder(tmpFolderRoot.getName() + "/" + StringResources.randomString(5));

		if (!tmpFolder1.exists() || tmpFolder1.isFile() || !tmpFolder2.exists() || tmpFolder2.isFile()) {
			logger.error("failed to create tmp folder, nonexisted. check data path.");
			return false;
		}

		HashMap<String, SrcFunction> tmpFileFunctionMap = new HashMap<>();
		for (SrcFunction srcFunction : functions1) {
			String tmpFilePath = tmpFolder1.getAbsolutePath() + "/" + srcFunction.id + ".cpp";
			File file = new File(tmpFilePath);
			Lines.flushToFile(Lines.from(srcFunction.content), file.getCanonicalPath(), Charsets.UTF_8);
			tmpFileFunctionMap.put(file.getCanonicalPath(), srcFunction);
		}
		for (SrcFunction srcFunction : functions2) {
			String tmpFilePath = tmpFolder2.getAbsolutePath() + "/" + srcFunction.id + ".cpp";
			File file = new File(tmpFilePath);
			Lines.flushToFile(Lines.from(srcFunction.content), file.getCanonicalPath(), Charsets.UTF_8);
			tmpFileFunctionMap.put(file.getCanonicalPath(), srcFunction);
		}

		File tmpFile1 = DmasApplication.createTmpFile(tmpFolderRoot.getName() + "/" + StringResources.randomString(5));
		File tmpFile2 = DmasApplication.createTmpFile(tmpFolderRoot.getName() + "/" + StringResources.randomString(5));

		File fmatricFile3 = DmasApplication
				.createTmpFile(tmpFolderRoot.getName() + "/" + StringResources.randomString(5));

		File cmatricFile3 = DmasApplication
				.createTmpFile(tmpFolderRoot.getName() + "/" + StringResources.randomString(5));

		try {

			int lc = Pool.numberOfLogicalCores();
			lc = lc / 2 + 1;
			lc = lc < 1 ? 1 : lc;

			String[] arg = new String[] { PATH_CCFINDERX_EXE, "d", "cpp", "-o", tmpFile1.getAbsolutePath(), "-dn",
					tmpFolder1.getAbsolutePath(), "-is", "-dn", tmpFolder2.getAbsolutePath(), "-w", "f-w-g+", "-b",
					Integer.toString(b), "-t", Integer.toString(t), "--threads=" + lc };
			logger.info(StringResources.JOINER_TOKEN.join(arg));
			ProcessBuilder pb = new ProcessBuilder(arg);
			pb.environment().put("CCFINDERX_PYTHON_INTERPRETER_PATH", PATH_PYTHON26);
			pb.redirectOutput(Redirect.INHERIT);
			pb.redirectError(Redirect.INHERIT);
			Process p = pb.start();
			p.waitFor();
			arg = new String[] { PATH_CCFINDERX_EXE, "p", tmpFile1.getAbsolutePath() + ".ccfxd" };
			logger.info(StringResources.JOINER_TOKEN.join(arg));
			pb = new ProcessBuilder(arg);
			pb.redirectOutput(Redirect.to(tmpFile2));
			pb.redirectError(Redirect.INHERIT);
			p = pb.start();
			p.waitFor();

			// metrics:
			arg = new String[] { PATH_CCFINDERX_EXE, "m", tmpFile1.getAbsolutePath() + ".ccfxd", "-c", "-o",
					cmatricFile3.getAbsolutePath(), "-f", "-o", fmatricFile3.getAbsolutePath() };
			logger.info(StringResources.JOINER_TOKEN.join(arg));
			pb = new ProcessBuilder(arg);
			pb.redirectError(Redirect.INHERIT);
			pb.redirectOutput(Redirect.INHERIT);
			p = pb.start();
			p.waitFor();
		} catch (Exception e) {
			logger.error("Failed to execute ccfinder. check input and path.", e);
			DmasFileOperations.deleteRecursively(tmpFolderRoot.getAbsolutePath());
			return false;
		}

		// load matrixs:
		TIntDoubleHashMap cloneMetric = new TIntDoubleHashMap();
		TIntDoubleHashMap fileMetric = new TIntDoubleHashMap();
		Lines tmpLines = Lines.fromFile(cmatricFile3.getAbsolutePath());
		boolean skip = true;
		for (String line : tmpLines) {
			if (skip) {
				skip = false;
				continue;
			}
			String[] parts = line.split("\t");
			if (parts.length < 2) {
				logger.error("Error line detected in clone metric file {}", line);
				continue;
			}
			cloneMetric.put(Integer.parseInt(parts[0]), Double.parseDouble(parts[1]));
		}
		tmpLines = Lines.fromFile(fmatricFile3.getAbsolutePath());
		skip = true;
		for (String line : tmpLines) {
			if (skip) {
				skip = false;
				continue;
			}
			String[] parts = line.split("\t");
			if (parts.length < 2) {
				logger.error("Error line detected in clone metric file {}", line);
				continue;
			}
			fileMetric.put(Integer.parseInt(parts[0]), Double.parseDouble(parts[1]));
		}

		// load clones from file:
		Lines lines;
		try {
			lines = Lines.fromFile(tmpFile2.getAbsolutePath());
		} catch (Exception e) {
			logger.error("Failed to load the output file..");
			DmasFileOperations.deleteRecursively(tmpFolderRoot.getAbsolutePath());
			return false;
		}

		boolean clonemap_start = false;
		boolean filemap_start = false;
		ArrayList<String> cloneLines = new ArrayList<>();
		TIntObjectHashMap<SrcFunction> functionMap = new TIntObjectHashMap<>();
		TLongObjectHashMap<SrcFunction> functionMapLongIDS = new TLongObjectHashMap<>();

		for (String line : lines) {
			if (line.equals("source_files {")) {
				filemap_start = true;
				continue;
			}
			if (line.equals("clone_pairs {")) {
				clonemap_start = true;
				continue;
			}
			if (filemap_start && line.equals("}"))
				filemap_start = false;
			if (clonemap_start && line.equals("}"))
				clonemap_start = false;
			if (clonemap_start) {
				cloneLines.add(line);
			}
			if (filemap_start) {
				String[] parts = line.split("\t");
				File tfile = new File(parts[1]);
				SrcFunction srcFunction = tmpFileFunctionMap.get(tfile.getCanonicalPath());
				functionMap.put(Integer.parseInt(parts[0]), srcFunction);
				functionMapLongIDS.put(srcFunction.id, srcFunction);
			}
		}

		// calculate the clone weights:
		HashMap<String, ArrayList<ArrayList<int[]>>> cloneWeightMap = new HashMap<>();
		for (String line : cloneLines) {

			String[] parts = line.split("\t");

			String[] sparts = getM.split(parts[1]);
			Integer src_id = Integer.parseInt(sparts[0]);
			int[] src_range = new int[] { Integer.parseInt(sparts[1]), Integer.parseInt(sparts[2]) };

			sparts = getM.split(parts[2]);
			Integer des_id = Integer.parseInt(sparts[0]);
			int[] des_range = new int[] { Integer.parseInt(sparts[1]), Integer.parseInt(sparts[2]) };

			if (src_id.equals(des_id))
				continue;

			String cmapping;
			if (src_id < des_id)
				cmapping = StringResources.JOINER_TOKEN.join(src_id, des_id);
			else
				cmapping = StringResources.JOINER_TOKEN.join(des_id, src_id);

			ArrayList<ArrayList<int[]>> ranges = cloneWeightMap.get(cmapping);
			if (ranges == null) {
				ranges = new ArrayList<>();
				ranges.add(new ArrayList<>());
				ranges.add(new ArrayList<>());
				cloneWeightMap.put(cmapping, ranges);
			}
			if (src_id < des_id) {
				ranges.get(0).add(src_range);
				ranges.get(1).add(des_range);
			} else {
				ranges.get(1).add(src_range);
				ranges.get(0).add(des_range);
			}

			// srcFunction.clones.add(tarFunction.id);
			// tarFunction.clones.add(srcFunction.id);

		}

		for (Entry<String, ArrayList<ArrayList<int[]>>> entry : cloneWeightMap.entrySet()) {
			String[] parts = entry.getKey().split(StringResources.STR_TOKENBREAK);
			int src_id = Integer.parseInt(parts[0]);
			int des_id = Integer.parseInt(parts[1]);

			if (src_id == des_id)
				continue;

			ArrayList<int[]> src_ranges, des_ranges;
			if (src_id < des_id) {
				src_ranges = entry.getValue().get(0);
				des_ranges = entry.getValue().get(1);
			} else {
				src_ranges = entry.getValue().get(1);
				des_ranges = entry.getValue().get(0);
			}

			double src_range = range(src_ranges);
			double des_range = range(des_ranges);

			double src_length = fileMetric.get(src_id);
			double des_length = fileMetric.get(des_id);

			double weight = (src_range + des_range) / (src_length + des_length);

			// logger.info("({} + {}) / ({} + {})", src_range, des_range,
			// src_length, des_length, weight);

			if (weight < 0.01)
				continue;

			SrcFunction srcFunction = functionMap.get(src_id);
			SrcFunction tarFunction = functionMap.get(des_id);

			if (verify(srcFunction) && verify(tarFunction)) {
				srcFunction.clones.add(new EntryPair<Long, Double>(tarFunction.id, weight));
				tarFunction.clones.add(new EntryPair<Long, Double>(srcFunction.id, weight));
			}
		}

		// add clone by hashing the complete src function
		// for short source codes ccfinderx failed to identify as clone
		// as they do not satisfy ccfinerx's minimun cloned sequence threshold.
		for (SrcFunction fsrc1 : functions1) {
			for (SrcFunction fsrc2 : functions2) {
				if (fsrc1.id == fsrc2.id)
					continue;
				if (!verify(fsrc1))
					continue;
				if (!verify(fsrc2))
					continue;

				ArrayList<String> pcontent1 = new ArrayList<>();
				ArrayList<String> pcontent2 = new ArrayList<>();
				for (int i = 0; i < fsrc1.content.size(); ++i) {
					if (!fsrc1.content.get(i).trim().equals(""))
						pcontent1.add(fsrc1.content.get(i).trim());
				}
				for (int i = 0; i < fsrc2.content.size(); ++i) {
					if (!fsrc2.content.get(i).trim().equals(""))
						pcontent2.add(fsrc2.content.get(i).trim());
				}
				if (StringResources.JOINER_TOKEN.join(pcontent1).equals(StringResources.JOINER_TOKEN.join(pcontent2))) {
					addClone(fsrc1, fsrc2);
					addClone(fsrc2, fsrc1);
				}
			}
		}

		DmasFileOperations.deleteRecursively(tmpFolderRoot.getAbsolutePath());
		return true;

	}

	private static void addClone(SrcFunction fsrc1, SrcFunction fsrc2) {
		EntryPair<Long, Double> cpaire = null;
		for (EntryPair<Long, Double> pair : fsrc1.clones) {
			if (pair.key.equals(fsrc2.id)) {
				cpaire = pair;
				break;
			}
		}
		if (cpaire == null) {
			cpaire = new EntryPair<Long, Double>(fsrc2.id, 1.0);
			fsrc1.clones.add(cpaire);
		} else
			cpaire.value = 1.0;
	}

	public static int range(Iterable<int[]> ranges) {
		int min = Integer.MAX_VALUE;
		int max = Integer.MIN_VALUE;
		for (int[] is : ranges) {
			if (is.length != 2) {
				logger.error("The input should be a list of range [start, end]");
				return 0;
			}
			min = is[0] < min ? is[0] : min;
			max = is[1] > max ? is[1] : max;
		}
		return max - min + 1;
	}

	public static void main(String[] args) throws Exception {
		// Environment.init();
		// ca.mcgill.sis.dmas.env.linker.ccfinderHome =
		// "C:\\ding\\datafolder\\ccfindertest\\";
		//
		// SrcFunctions f1 = SrcFunctionUtils.getSrcFunctions(new
		// File(DmasApplication.applyDataContext("1.json")));
		// SrcFunctions f2 = SrcFunctionUtils.getSrcFunctions(new
		// File(DmasApplication.applyDataContext("2.json")));
		//
		// SrcCloneDetectorCppCCfinder detector = new SrcCloneDetectorCppCCfinder(
		// ca.mcgill.sis.dmas.env.linker.ccfinderHome,
		// ca.mcgill.sis.dmas.env.linker.ccfinderPython26exe, 15,
		// 3);
		//
		// detector.detectClones(f1, f2);

	}

	@Override
	public boolean isValid() {
		return this.validCCfinder;
	}
}
