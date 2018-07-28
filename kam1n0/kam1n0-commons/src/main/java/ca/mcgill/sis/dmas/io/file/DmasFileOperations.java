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
package ca.mcgill.sis.dmas.io.file;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.env.DmasApplication;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.binary.DmasByteOperation;

public class DmasFileOperations {

	private static Logger logger = LoggerFactory.getLogger(DmasFileOperations.class);

	public static void deleteRecursivelyIfExisted(String path) throws Exception {
		if ((new File(DmasApplication.applyDataContext(path))).exists()) {
			deleteRecursively(path);
		}
	}

	public static void deleteRecursively(String path) throws Exception {
		path = DmasApplication.applyDataContext(path);
		Path directory = Paths.get(path);
		Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				Files.delete(file);
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
				Files.delete(dir);
				return FileVisitResult.CONTINUE;
			}

		});
	}

	@Deprecated
	public static void setFileAttribute(File file, String key, Object obj) throws Exception {
		Files.setAttribute(file.toPath(), "user:" + key, ByteBuffer.wrap(DmasByteOperation.convertToBytes(obj)));
	}

	@SuppressWarnings("unchecked")
	@Deprecated
	public static <T> T getFileAttribute(File file, String key) throws Exception {
		return (T) DmasByteOperation.convertFromBytes((byte[]) Files.getAttribute(file.toPath(), "user:" + key));
	}

	public static Pattern REGEX_A = Pattern.compile("\\.a$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_STRIP = Pattern.compile("\\.strip$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_UNSTRIP = Pattern.compile("\\.unstrip$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_SO = Pattern.compile("\\.so$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_O = Pattern.compile("\\.o$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_BIN = Pattern.compile("\\.bin$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_DLL = Pattern.compile("\\.dll$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_EXE = Pattern.compile("\\.exe$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_CPP = Pattern.compile("\\.cpp$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_C = Pattern.compile("\\.c$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_CC = Pattern.compile("\\.cc$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_H = Pattern.compile("\\.h$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_ASM = Pattern.compile("\\.asm$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_JSON = Pattern.compile("\\.json$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_LOG = Pattern.compile("\\.log$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_I64 = Pattern.compile("\\.i64$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_TAG = Pattern.compile("\\.tagged$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_IDB = Pattern.compile("\\.idb$", Pattern.CASE_INSENSITIVE);
	public static Pattern REGEX_ALL = Pattern.compile(StringResources.REGEX_ANY);

	public static File replaceExtension(File file, String newExtension) {
		String name = file.getName().substring(0, file.getName().lastIndexOf('.'));
		return new File(file.getParentFile().getAbsolutePath() + "/" + name + newExtension);
	}

	public static ArrayList<File> select(String path, final Pattern... patterns) throws Exception {
		return select(path, false, patterns);
	}

	public static ArrayList<File> selectNoException(String path, final Pattern... patterns) {
		try {
			return select(path, false, patterns);
		} catch (Exception e) {
			logger.error("Failed to find " + Arrays.toString(patterns) + " for " + path, e);
			return new ArrayList<>();
		}
	}

	public static ArrayList<File> select(String path, boolean includeNoExtensions, final Pattern... patterns)
			throws Exception {
		final ArrayList<File> files = new ArrayList<File>();
		path = DmasApplication.applyDataContext(path);
		Path directory = Paths.get(path);
		if (directory.toFile().isFile()) {
			files.add(directory.toFile());
			return files;
		}
		Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				File tfile = file.toFile();
				boolean add = false;
				if (includeNoExtensions && !tfile.getName().contains(".")) {
					add = true;
				}
				for (Pattern pattern : patterns) {
					if (pattern.matcher(tfile.getName().trim()).find()) {
						add = true;
						break;
					}
				}
				if (add)
					files.add(tfile);
				return FileVisitResult.CONTINUE;
			}

		});
		return files;
	}

	public static ArrayList<File> select(String path, final String... regexs) {
		List<Pattern> patterns = Arrays.stream(regexs).map(Pattern::compile).collect(Collectors.toList());
		final ArrayList<File> files = new ArrayList<File>();
		path = DmasApplication.applyDataContext(path);
		Path directory = Paths.get(path);
		try {
			Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
					File tfile = file.toFile();
					for (Pattern pattern : patterns) {
						if (pattern.matcher(tfile.getName().trim()).find()) {
							files.add(tfile);
							break;
						}
					}
					return FileVisitResult.CONTINUE;
				}

			});
		} catch (IOException e) {
			logger.error("Failed to select files from directory. Returning null.", e);
			return null;
		}
		return files;
	}

	public static ArrayList<File> selectDirectories(String path) throws Exception {
		final ArrayList<File> files = new ArrayList<File>();
		path = DmasApplication.applyDataContext(path);
		Path directory = Paths.get(path);
		Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
				File tfile = dir.toFile();
				if (tfile.isDirectory()) {
					files.add(tfile);
				}
				return FileVisitResult.CONTINUE;
			};

		});
		return files;
	}

	public static List<File> copyAllFiles(String sourceDir, String destinationDir, Predicate<File> filter,
			Predicate<File> selectCopiedFiles) throws IOException {
		List<File> copiedFilesThatFullyMatchedFilter = new ArrayList<>();
		File srcDir = new File(sourceDir);
		Files.walkFileTree(srcDir.toPath(), new SimpleFileVisitor<Path>() {

			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				if (filter.test(file.toFile())) {
					File bin = file.toFile();
					String destinationFile = bin.getAbsolutePath().replaceFirst(Pattern.quote(srcDir.getAbsolutePath()),
							destinationDir);
					File bin_to = new File(destinationFile);
					bin_to.getParentFile().mkdirs();
					com.google.common.io.Files.copy(bin, bin_to);
					if (selectCopiedFiles.test(bin)) {
						copiedFilesThatFullyMatchedFilter.add(bin);
					}
				}
				return FileVisitResult.CONTINUE;
			}

			@Override
			public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
				File tfile = dir.toFile();
				if (tfile.isDirectory()) {
				}
				return FileVisitResult.CONTINUE;
			};

		});

		return copiedFilesThatFullyMatchedFilter;
	}

	public static boolean equal(File f1, File f2) {
		try {
			return f1.getCanonicalPath().equals(f2.getCanonicalPath());
		} catch (IOException e) {
			logger.error("Failed to determine if " + f1.getAbsolutePath() + " and " + f2.getAbsolutePath()
					+ " is equivalent.", e);
			return false;
		}
	}
}
