package ca.mcgill.sis.dmas.kam1n0.app;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FileUtils;
import org.openqa.selenium.*;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import ca.mcgill.sis.dmas.env.StringResources;

import static org.springframework.util.FileSystemUtils.deleteRecursively;

public class UITestUtils {
	private static Process appProcess;
	private static File tempDirectory;
	public static void log(String msg, Object... args) {
		System.out.println(StringResources
				.parse(UITest.class.getSimpleName() + " " + StringResources.timeString() + " " + msg, args));
	}

	public static void debugWithExistingServer(String dataDirectory) throws Exception {
		appProcess = null;
		tempDirectory = new File(dataDirectory);
		log("Debugging using server already running on {}", tempDirectory.getAbsolutePath());
	}

	public static void startServer() throws Exception {
		tempDirectory = Files.createTempDirectory("Kam1n0-TESTING-" + StringResources.timeString()).toFile();
		log("Starting server on {}", tempDirectory.getAbsolutePath());
		ProcessBuilder builder = new ProcessBuilder();
		String binLocation = System.getProperty("output.dir");
		log("Bin directory is on {}", binLocation);
		appProcess = builder.command("java",
				"-Xmx6G",
				"-Xss4m",
				"\"-Dkam1n0.ansi.enable=false\"",
				"\"-Dkam1n0.spring.popup=false\"",
				"\"-Dlogging.level.org.springframework=INFO\"",
				"\"-Djdk.attach.allowAttachSelf=true\"",
				"--add-exports=java.base/jdk.internal.misc=ALL-UNNAMED",
				"--add-exports=java.base/jdk.internal.ref=ALL-UNNAMED",
				"--add-exports=java.base/sun.nio.ch=ALL-UNNAMED",
				"--add-exports=java.management.rmi/com.sun.jmx.remote.internal.rmi=ALL-UNNAMED",
				"--add-exports=java.rmi/sun.rmi.registry=ALL-UNNAMED",
				"--add-exports=java.rmi/sun.rmi.server=ALL-UNNAMED",
				"--add-exports=java.sql/java.sql=ALL-UNNAMED",
				"--add-opens=java.base/java.lang=ALL-UNNAMED",
				"--add-opens=java.base/java.lang.module=ALL-UNNAMED",
				"--add-opens=java.base/jdk.internal.loader=ALL-UNNAMED",
				"--add-opens=java.base/jdk.internal.ref=ALL-UNNAMED",
				"--add-opens=java.base/jdk.internal.reflect=ALL-UNNAMED",
				"--add-opens=java.base/jdk.internal.math=ALL-UNNAMED",
				"--add-opens=java.base/jdk.internal.module=ALL-UNNAMED",
				"--add-opens=java.base/jdk.internal.util.jar=ALL-UNNAMED",
				"--add-opens=jdk.management/com.sun.management.internal=ALL-UNNAMED",
				"-jar",	binLocation + "kam1n0-server.jar",
				"--start", "kam1n0.data.path", tempDirectory.getAbsolutePath())
				.inheritIO().start();
	}

	public static void cleanUp() throws Exception {
		log("UITestUtils Start Cleaning up...");
		if (appProcess != null) {
			appProcess.destroy();
			if (appProcess.isAlive())
				appProcess.destroyForcibly();

			TimeUnit.SECONDS.sleep(5);
			deleteRecursively(tempDirectory);
		} else {
			log("Was debugging using a server already running on {}", tempDirectory.getAbsolutePath());
			log("Files were NOT deleted as server might still be running.");
		}

		log("UITestUtils Cleaning up End.");
	}

	/**
	 * From
	 * https://sqa.stackexchange.com/questions/22191/is-it-possible-to-automate-drag-and-drop-from-a-file-in-system-to-a-website-in-s
	 * 
	 * @param filePath
	 * @param target
	 * @param driver
	 * @param offsetX
	 * @param offsetY
	 */
	public static void DropFile(File filePath, WebElement target, WebDriver driver, int offsetX, int offsetY) {
		if (!filePath.exists())
			throw new WebDriverException("File not found: " + filePath.toString());

		JavascriptExecutor jse = (JavascriptExecutor) driver;
		WebDriverWait wait = new WebDriverWait(driver, 30);

		String JS_DROP_FILE = "var target = arguments[0]," + "    offsetX = arguments[1],"
				+ "    offsetY = arguments[2]," + "    document = target.ownerDocument || document,"
				+ "    window = document.defaultView || window;" + "" + "var input = document.createElement('INPUT');"
				+ "input.type = 'file';" + "input.style.display = 'none';" + "input.onchange = function () {"
				+ "  var rect = target.getBoundingClientRect(),"
				+ "      x = rect.left + (offsetX || (rect.width >> 1)),"
				+ "      y = rect.top + (offsetY || (rect.height >> 1)),"
				+ "      dataTransfer = { files: this.files };" + ""
				+ "  ['dragenter', 'dragover', 'drop'].forEach(function (name) {"
				+ "    var evt = document.createEvent('MouseEvent');"
				+ "    evt.initMouseEvent(name, !0, !0, window, 0, 0, 0, x, y, !1, !1, !1, !1, 0, null);"
				+ "    evt.dataTransfer = dataTransfer;" + "    target.dispatchEvent(evt);" + "  });" + ""
				+ "  setTimeout(function () { document.body.removeChild(input); }, 25);" + "};"
				+ "document.body.appendChild(input);" + "return input;";

		WebElement input = (WebElement) jse.executeScript(JS_DROP_FILE, target, offsetX, offsetY);
		input.sendKeys(filePath.getAbsoluteFile().toString());
		wait.until(ExpectedConditions.stalenessOf(input));
	}

	public static void takeScreenshot(String pathname, WebDriver driver) throws IOException {
		File src = ((TakesScreenshot) driver).getScreenshotAs(OutputType.FILE);
		FileUtils.copyFile(src, new File(pathname));
	}

	public static void deleteTempFiles() {
		deleteRecursively(Paths.get(tempDirectory.getAbsolutePath(), "tmp", "admin").toFile());
	}
}
