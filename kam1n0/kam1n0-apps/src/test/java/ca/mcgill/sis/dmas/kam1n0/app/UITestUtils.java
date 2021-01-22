package ca.mcgill.sis.dmas.kam1n0.app;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.impl.disassembly.DisassemblyFactoryIDA;

public class UITestUtils {
	private static Process appProcess;

	public static void log(String msg, Object... args) {
		System.out.println(StringResources
				.parse(UITest.class.getSimpleName() + " " + StringResources.timeString() + " " + msg, args));
	}

	public static File StartServer() throws Exception {
		File dataPath = Files.createTempDirectory("Kam1n0-TESTING-" + StringResources.timeString()).toFile();
		dataPath.deleteOnExit();
		log("Starting server on {}", dataPath.getAbsolutePath());
		ProcessBuilder builder = new ProcessBuilder();
		String binLocation = System.getProperty("output.dir");
		log("Bin directory is on {}", binLocation);
		appProcess = builder.command("java", "-Xmx6G", "-Xss4m", "-Dkam1n0.ansi.enable=false",
				"-Dkam1n0.spring.popup=false", "-Dlogging.level.org.springframework=INFO", "-jar",
				binLocation + "kam1n0-server.jar", "--start", "kam1n0.data.path", dataPath.getAbsolutePath())
				.inheritIO().start();

		return dataPath;
	}

	public static void cleanUp() throws Exception {
		log("Cleaning up...");
		if (appProcess != null)
			appProcess.destroyForcibly();

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

}
