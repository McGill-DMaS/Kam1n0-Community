package ca.mcgill.sis.dmas.res;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

import org.apache.commons.lang3.SystemUtils;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;

import static org.fusesource.jansi.Ansi.*;
import static org.fusesource.jansi.Ansi.Color.*;

/**
 * The built jar of this class should be in the same folder as the resource bin
 * folder. If it is in IDE, it will automatically set to the bin folder under
 * the kam1n0-resources project.
 * 
 */
public class KamResourceLoader {

	public static String VERSION = "2.0.0";
	public static volatile boolean runningInsideIDE;
	public static String jPath;
	public static String jPath_file;
	public static String bin_non_distributed;
	public static volatile boolean useAnsi = false;

	private static void print(String val) {
		val = "  [ResourceCtrl] " + val;
		if (useAnsi)
			System.out.println(ansi().fg(Color.YELLOW).a(val).reset());
		else
			System.out.println(val);
	}

	public static Ansi colorHighlight(String val) {
		return ansi().fg(Color.CYAN).bold().a(val).reset();
	}

	static {

		File jar;
		try {
			URI uri = KamResourceLoader.class.getProtectionDomain().getCodeSource().getLocation().toURI();
			// loaded by spring.
			if (uri.toString().contains("!/BOOT-INF/")) {
				String jarStr = uri.toString().substring(0, uri.toString().indexOf("!/BOOT-INF/"));
				jar = new File(jarStr.replace("jar:file:/", ""));
			} else
				jar = new File(
						KamResourceLoader.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
			jPath_file = jar.getAbsolutePath();
			jPath = jar.getParentFile().getAbsolutePath();
			if (jar.getName().equals("classes")) {
				runningInsideIDE = true;
				System.setProperty("kam1n0.inIDE", "true");
				jPath = jar.getParentFile().getParentFile().getAbsolutePath() + "/bin/";
			} else {
				runningInsideIDE = false;
			}

			if (SystemUtils.IS_OS_WINDOWS && !runningInsideIDE
					&& System.getProperty("kam1n0.ansi.enable", "true").equalsIgnoreCase("true")) {
				useAnsi = true;
				AnsiConsole.systemInstall();
				print("Detected run in terminal. Installed ansi coloring terminal.");
			} else
				useAnsi = false;

			// print("VAR: runningInsideIDE " + runningInsideIDE);
			// print("VAR: useAnsi " + useAnsi);
			// print("VAR: kam1n0.ansi.enable " + System.getProperty("kam1n0.ansi.enable",
			// "true"));

			print("Kam1n0 Resource URI:" + uri);
			if (runningInsideIDE)
				print("Detected run in eclipse or other IDE; Setting resources JAR Path to current project root.");

		} catch (URISyntaxException e) {
			runningInsideIDE = false;
			print("Failed to initialize the jar path; setting to working directory." + e.getMessage());
			e.printStackTrace();
			jPath = System.getProperty("user.dir");
			jPath_file = System.getProperty("user.dir");
			print("Setting jPath and jPath_file to " + jPath);
		}
		bin_non_distributed = (new File(jPath)).getParentFile().getAbsolutePath() + "/bin-exclude-from-distr";
		print("Setting Reources Folder to " + jPath);
		try {
			addLibraryPath(jPath + "/lib/");
		} catch (Exception e) {
			print("Error. Failed to add new lib path. " + e.getMessage());
			e.printStackTrace();
		}
	}

	public static File loadFile(String relativePathToResourceFolder) {
		File file = new File(jPath + "/" + relativePathToResourceFolder);
		if (file.exists())
			return file;
		return null;
	}

	public static File writeFile(String relativePathToResourceFolder) {
		File file = new File(jPath + "/" + relativePathToResourceFolder);
		return file;
	}

	/**
	 * Read/Write access
	 * 
	 * @param relativePathToResourceFolder
	 * @return
	 */
	public static File getFileThatWillNotInDistribution(String relativePathToResourceFolder) {
		File file = new File(bin_non_distributed + "/" + relativePathToResourceFolder);
		return file;
	}

	public static void loadLibrary(String librayName) {
		System.loadLibrary(librayName);
	}

	public static void addLibraryPath(String pathToAdd) throws Exception {
		Field usrPathsField = ClassLoader.class.getDeclaredField("usr_paths");
		usrPathsField.setAccessible(true);

		String[] paths = (String[]) usrPathsField.get(null);

		for (String path : paths)
			if (path.equals(pathToAdd))
				return;

		String[] newPaths = Arrays.copyOf(paths, paths.length + 1);
		newPaths[newPaths.length - 1] = pathToAdd;
		usrPathsField.set(null, newPaths);
	}
}
