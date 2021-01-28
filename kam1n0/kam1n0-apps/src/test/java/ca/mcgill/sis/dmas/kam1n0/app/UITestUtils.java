package ca.mcgill.sis.dmas.kam1n0.app;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

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

	public static void StartServer() throws Exception {
		tempDirectory = Files.createTempDirectory("Kam1n0-TESTING-" + StringResources.timeString()).toFile();
		//dataPath.deleteOnExit();
		log("Starting server on {}", tempDirectory.getAbsolutePath());
		ProcessBuilder builder = new ProcessBuilder();
		String binLocation = System.getProperty("output.dir");
		log("Bin directory is on {}", binLocation);
		appProcess = builder.command("java", "-Xmx6G", "-Xss4m", "-Dkam1n0.ansi.enable=false",
				"-Dkam1n0.spring.popup=false", "-Dlogging.level.org.springframework=INFO", "-jar",
				binLocation + "kam1n0-server.jar", "--start", "kam1n0.data.path", tempDirectory.getAbsolutePath())
				.inheritIO().start();
	}

	public static void cleanUp() throws Exception {
		log("UITestUtils Start Cleaning up...");
		if (appProcess != null) {
			appProcess.destroy();
			if (appProcess.isAlive())
				appProcess.destroyForcibly();
		}
		Thread.sleep(1000*5); // 5 seconds
		deleteRecursively(tempDirectory);

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
}
