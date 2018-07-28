package ca.mcgill.sis.dmas.kam1n0.app.util;

import java.io.File;
import java.lang.reflect.Constructor;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalListener;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.kam1n0.UserController;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;

public class FileServingUtils {

	private static Logger logger = LoggerFactory.getLogger(FileServingUtils.class);

	private static RemovalListener<Long, AutoCloseable> removalListener = ent -> {
		logger.info("Removing expired result {}..", ent.getKey());
		if (ent.getValue() != null) {
			AutoCloseable clResult = ent.getValue();
			try {
				clResult.close();
			} catch (Exception e) {
				logger.error("Failed to clone resource .", e);
			}
		}
	};

	public static Cache<Long, AutoCloseable> fileServingObjectCached = CacheBuilder.newBuilder().concurrencyLevel(4)
			.maximumSize(20).expireAfterAccess(10, TimeUnit.MINUTES).removalListener(removalListener).build();

	/***
	 * https://stackoverflow.com/questions/1184176/how-can-i-safely-encode-a-string-in-java-to-use-as-a-filename
	 * 
	 * @param fileName
	 * @return
	 */
	public static String escapeName(String fileName) {
		char fileSep = '/'; // ... or do this portably.
		char escape = '%'; // ... or some other legal char.
		int len = fileName.length();
		StringBuilder sb = new StringBuilder(len);
		for (int i = 0; i < len; i++) {
			char ch = fileName.charAt(i);
			if (ch < ' ' || ch >= 0x7F || ch == fileSep // || ... // add other illegal chars
					|| (ch == '.' && i == 0) // we don't want to collide with "." or ".."!
					|| ch == escape) {
				sb.append(escape);
				if (ch < 0x10) {
					sb.append('0');
				}
				sb.append(Integer.toHexString(ch));
			} else {
				sb.append(ch);
			}
		}
		return fileName.trim();
	}

	public static <T extends AutoCloseable> T getFileRelatedObject(String fileName, Class<T> claz) {
		fileName = escapeName(fileName);
		String userName = UserController.findUserName();
		long id = HashUtils.constructID(userName.getBytes(), fileName.getBytes());
		fileServingObjectCached.cleanUp(); // important!
		@SuppressWarnings("unchecked")
		T val = (T) fileServingObjectCached.getIfPresent(id);
		if (val == null) {
			try {
				File file = new File(Environment.getUserFolder(userName) + "/" + fileName);
				if (file.exists()) {
					FileInfo info = FileInfo.readFileInfo(file);
					if (info.appId == -1 || info.appType == null)
						throw new Exception("Metadata is missing for file " + file.getAbsolutePath());
					Constructor<T> constructor = claz.getDeclaredConstructor(new Class[] { Long.class, File.class });
					val = (T) constructor.newInstance(info.appId, file);
					fileServingObjectCached.put(id, val);
					return val;
				} else
					return null;
			} catch (Exception e) {
				logger.error("Failed to load file from " + fileName + " for " + userName, e);
				return null;
			}
		}
		return val;
	}

	public static void dropFile(String fileName) {
		fileName = escapeName(fileName);
		String userName = UserController.findUserName();
		long id = HashUtils.constructID(userName.getBytes(), fileName.getBytes());
		fileServingObjectCached.invalidate(id);
		File file = new File(Environment.getUserFolder(userName) + "/" + fileName);
		if (file.exists())
			file.delete();
		file = new File(Environment.getUserFolder(userName) + "/" + fileName + ".meta");
		if (file.exists())
			file.delete();
	}

	public static void renameFile(String oldName, String newName) throws Exception {
		oldName = escapeName(oldName);
		newName = escapeName(newName);
		String userName = UserController.findUserName();
		long id = HashUtils.constructID(userName.getBytes(), oldName.getBytes());
		fileServingObjectCached.invalidate(id);

		File file = new File(Environment.getUserFolder(userName) + "/" + oldName);
		File fileNew = new File(Environment.getUserFolder(userName) + "/" + newName);

		File file_meta = new File(Environment.getUserFolder(userName) + "/" + oldName + ".meta");
		File fileNew_meta = new File(Environment.getUserFolder(userName) + "/" + newName + ".meta");

		if (file.renameTo(fileNew) && file_meta.renameTo(fileNew_meta)) {
			FileInfo info = FileInfo.readFileInfo(fileNew);
			info.file = newName;
			info.save();
		}

	}

}
