package ca.mcgill.sis.dmas.kam1n0.app;

import static org.junit.Assert.*;
import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.junit.*;
import org.openqa.selenium.*;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.logging.LogType;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.res.KamResourceLoader;
import static ca.mcgill.sis.dmas.kam1n0.app.UITestUtils.log;

public class UITest {
	private static ChromeDriver driver;
	List<String> errorStrings = Arrays.asList("SyntaxError", "EvalError", "ReferenceError", "RangeError", "TypeError",
			"URIError");

	private static boolean isDebuggingWithExistingServer = false;

	@BeforeClass
	public static void prepareServerAndBrowser() throws Exception {

		String existingServerDataFolder = System.getProperty("debugWithExistingServer");
		if ( existingServerDataFolder != null ) {
			UITestUtils.debugWithExistingServer(existingServerDataFolder);
			isDebuggingWithExistingServer = true;
		} else {
			UITestUtils.startServer();
		}

		String envp = System.getenv().get("webdriver.chrome.driver");
		System.setProperty("webdriver.chrome.driver", envp);

		ChromeOptions options = new ChromeOptions();
		options.addArguments("--start-maximized");
		options.setExperimentalOption("useAutomationExtension", false);
		driver = new ChromeDriver(options);

		if (!isDebuggingWithExistingServer) {
			// Until we find a proper way to know when the server is ready to process requests, we simply sleep for a while
			final int timeToWaitForServerSecond = 40;
			log("Waiting {} seconds for server to be ready...", timeToWaitForServerSecond);
			Thread.sleep(1000 * timeToWaitForServerSecond);
		}

		register();
		login();
	}

	@AfterClass
	public static void cleanUp() throws Exception {
		log("UITest Cleaning up...");
		if (driver != null) {

			driver.quit();
		}

		UITestUtils.cleanUp();
	}

	@After
	public void CloseAllPage(){
		String parentWindowHandler = driver.getWindowHandle(); // Store your parent window
		Set<String> handles = new HashSet<>(driver.getWindowHandles());
		handles.remove(parentWindowHandler);

		for (String windowHandler : handles) {
			WebDriver win = driver.switchTo().window(windowHandler);
			log("Close page:" + win.getTitle());
			driver.close();
		}
		driver.switchTo().window(parentWindowHandler);
		UITestUtils.deleteTempFiles();
	}

	public void assertNoJSError() {
		List<LogEntry> anyErr = driver.manage().logs().get(LogType.BROWSER).getAll().stream()
				.filter(lg -> errorStrings.stream().filter(err -> lg.getMessage().contains(err)).findAny().isPresent())
				.collect(Collectors.toList());
		if (anyErr.size() > 0)
			log("JS Errors {}", anyErr);
		assertFalse(anyErr.size() > 0);
	}

	public static void register() throws Exception {

		log("Testing register...");
		driver.get("http://127.0.0.1:8571/register");

		WebDriverWait wait = new WebDriverWait(driver, 30);
		wait.until(ExpectedConditions.urlContains("/register"));
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username")));

		driver.findElement(By.id("username")).sendKeys("admin");
		driver.findElement(By.id("email")).sendKeys("admin@dmas.com");
		driver.findElement(By.id("pw")).sendKeys("admin");
		driver.findElement(By.id("aggreeTLicense1")).click();
		driver.findElement(By.tagName("button")).click();

		if ( isDebuggingWithExistingServer ) {
			log("Debugging with existing server: assuming registration was fine or already done in a previous run. Waiting 5 seconds.");
			Thread.sleep(5000);
		} else {
			wait.until(ExpectedConditions.visibilityOfElementLocated(By.tagName("strong")));
			String response = driver.findElement(By.tagName("strong")).getText().trim().toLowerCase();
			assertEquals(response, "successfully");
		}
	}

	public static void login() throws Exception {
		log("Testing login...");
		driver.get("http://127.0.0.1:8571/login");
		driver.findElement(By.id("username")).sendKeys("admin");
		driver.findElement(By.id("password")).sendKeys("admin");
		driver.findElement(By.tagName("button")).click();

		WebDriverWait wait = new WebDriverWait(driver, 30);

		if ( isDebuggingWithExistingServer ) {
			log("Debugging with existing server: assuming login was fine and some apps perhaps already exist. Waiting 5 seconds.");
			Thread.sleep(5000);
		} else {
			wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("createAppId")));
		}

		String url = driver.getCurrentUrl();
		assertTrue(url.endsWith("/userHome"));
        log("{}", url);
		driver.executeScript("$(\"li.dropdown > a\").click()");
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.tagName("h6")));
		String userName = driver.findElement(By.tagName("h6")).getText().toLowerCase();
        log("{}", driver.getPageSource());
        log("{}", driver.findElement(By.tagName("body")).getText());
		log("{}", userName);
		assertTrue(userName.trim().equals("admin@dmas.com"));
	}

	public WebElement createApp(String appType) throws Exception {
		String identifier = appType + "_tmp_" + StringResources.timeString().replaceAll("\\s", "_");
		driver.get("http://127.0.0.1:8571/createApp");
		Select dropdown = new Select(driver.findElement(By.id("applicationType")));
		dropdown.selectByValue(appType);
		driver.findElement(By.id("name")).sendKeys(identifier);
		//driver.findElement(By.id("title")).sendKeys(identifier + "_title");
		driver.findElement(By.id("description")).sendKeys(identifier + "_desp");
		driver.findElement(By.id("btn_submit")).click();
		Thread.sleep(5000);
		String url = driver.getCurrentUrl();
		assertTrue(url.endsWith("/userHome"));
		WebElement title = driver.findElement(By.xpath("//h3[contains(text(), \"" + identifier + "\")]"));

		// return permanent link element
		WebElement ple = title.findElement(By.xpath("..")).findElement(By.cssSelector("h2 > a"));
		log("{}", ple.getText());
		return ple;

	}

	public void indexToApp(WebElement a_permanent_link, String testCaseFolder, String submit_btn_id) throws Exception {
		File folder = KamResourceLoader.getFileThatWillNotInDistribution(testCaseFolder);
		log("test case folder {}", folder.getAbsolutePath());
		List<File> bins = Arrays.asList(folder.listFiles()).stream().filter(f -> f.isFile())
				.collect(Collectors.toList());
		a_permanent_link.click();
		WebDriverWait wait = new WebDriverWait(driver, 30);
		wait.until(ExpectedConditions.urlContains("/home"));

		log("Current URL {}", driver.getCurrentUrl());
		assertTrue(driver.getCurrentUrl().endsWith("/home"));

		for (File bin : bins) {
			driver.get(driver.getCurrentUrl());
			driver.executeScript("$(\"a[href='#settings']\").click()");
			WebElement input = driver.findElement(By.id("index-upload-input"));
			WebElement btn = driver.findElement(By.id(submit_btn_id));
			input.sendKeys(bin.getAbsolutePath());
			btn.click();

			wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector("span.progress-label")));
			boolean error = false;
			do {
				Thread.sleep(1000);
				List<WebElement> prgs = driver.findElementsByCssSelector("div.progress.active");
				error = driver.findElementsByCssSelector("span.progress-label").stream()
						.filter(sp -> sp.getText().toLowerCase().contains("exception")).findAny().isPresent();
				assertFalse(error);
				if (prgs.size() == 0 || error)
					break;
			} while (true);

			driver.executeScript("window.scrollTo(0, document.body.scrollHeight)");
			wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("btn-conf-index-close")));
			btn = driver.findElement(By.id("btn-conf-index-close"));
			btn.click();
		}
	}

	public void searchFile(File file, String userHomeURL) throws Exception {
		log("Current URL {}", driver.getCurrentUrl());
		assertTrue(driver.getCurrentUrl().endsWith("/home"));
		driver.get(driver.getCurrentUrl());

		driver.executeScript("$(\"a[href='#messages']\").click()");
		WebElement input = driver.findElement(By.id("search-upload-input"));
		WebElement btn = driver.findElement(By.id("search-btn-binary"));
		input.sendKeys(file.getAbsolutePath());
		btn.click();

		WebDriverWait wait = new WebDriverWait(driver, 30);
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector("div.progress.active")));

		boolean error = false;
		do {
			List<WebElement> prgs = driver.findElementsByCssSelector("div.progress.active");
			error = driver.findElementsByCssSelector("span.progress-label").stream()
					.filter(sp -> sp.getText().toLowerCase().contains("exception")).findAny().isPresent();
			Thread.sleep(500);
			if (prgs.size() == 0 || error)
				break;
		} while (true);
		assertFalse(error);

		driver.get(userHomeURL);
		assertTrue(driver.getCurrentUrl().endsWith("/userHome"));

		WebElement element =  driver.findElementByCssSelector(".href-file-open");
		element.click();
		HashSet<String> handlers = new HashSet<>(driver.getWindowHandles());
		assertTrue(handlers.size() == 2);
		String original = driver.getWindowHandle();
		handlers.remove(original);
		driver.switchTo().window(handlers.stream().findAny().get());

		wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector(".card")));
		List<WebElement> cards = driver.findElementsByCssSelector(".card");
		log("{} cards", cards.size());
		assertTrue(cards.size() > 0);

		driver.executeScript("$(\"a[href='#details']\").click()");
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//span[contains(text(), 'adler32_z')]")));
		driver.executeScript("$(\"span:contains('adler32_z')\").click()");
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector(".fa-object-ungroup")));
		List<WebElement> entries = driver.findElementsByCssSelector(".fa-object-ungroup");
		log("{} entries", entries.size());
		assertTrue(entries.size() > 0);
		driver.switchTo().window(handlers.stream().findAny().get());
		driver.close();
		driver.switchTo().window(original);
		driver.get(userHomeURL);
	}

	public void searchExampleCode(String... views) throws Exception {
		log("Conducting searching example test");
		log("Current URL {}", driver.getCurrentUrl());
		assertTrue(driver.getCurrentUrl().endsWith("/home"));
		driver.executeScript("$(\"a[href='#profile']\").click()");

		WebDriverWait wait = new WebDriverWait(driver, 30);

		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("clone-func-example")));
		Select dropdown = new Select(driver.findElement(By.id("clone-func-example")));
		dropdown.selectByIndex(1);

		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("func-clone-btn")));
		WebElement btn = driver.findElement(By.id("func-clone-btn"));
		btn.click();

		String parentWindowHandler = driver.getWindowHandle(); // Store your parent window
		wait.until(ExpectedConditions.numberOfWindowsToBe(2));
		Set<String> handles = new HashSet<>(driver.getWindowHandles());
		handles.remove(parentWindowHandler);

		for (String subWindowHandler : handles) {
			String url;
			try {
				driver.switchTo().window(subWindowHandler);
				url = driver.getCurrentUrl();
				log("URL {}", url);
			} catch (WebDriverException e) {
				wait.until(ExpectedConditions.numberOfWindowsToBe(2));
				continue;
			}

			if (url.endsWith("/search_func/")) {
				wait.until(ExpectedConditions.numberOfWindowsToBe(2));
				assertNoJSError();
				log("Searching no JS error.");
			} else if (url.endsWith("/search_func_render")) {
				driver.executeScript("$(\"button[title='Open All']\").click()");
				driver.findElement(By.cssSelector("button[title='Open All']")).click();
				assertNoJSError();
				for (String view : views) {
					log("going to view {}", view);
					driver.executeScript("$(\"span[title='" + view + "']\").slice(0,3).click()");
					driver.switchTo().window(subWindowHandler);
				}

				Set<String> viewHandles = new HashSet<>(driver.getWindowHandles());
				viewHandles.remove(parentWindowHandler);
				viewHandles.remove(subWindowHandler);
				for (String viewWindowHandler : viewHandles) {
					WebDriver win = driver.switchTo().window(viewWindowHandler);
					log("checking view {}", win.getTitle());
					assertNoJSError();
					driver.close();
				}

				driver.switchTo().window(subWindowHandler);
				driver.close();
			}
		}

		driver.switchTo().window(parentWindowHandler);
	}

	@Test
	public void testDisassemblyFactory() throws Exception {
		log("Testing disassembly factory...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm-clone");
		indexToApp(ele, "test-cases/disassembly_test_case/", "index-btn");
	}

	@Test
	public void testAsmClone() throws Exception {
		log("Testing asm-clone...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm-clone");
		indexToApp(ele, "test-cases/asmclone/", "index-btn");
		searchExampleCode("Flow graph comparison.", "Full text alignment.", "Clone group alignment.");
	}

	@Test
	public void testAsm2Vec() throws Exception {
		log("Testing asm2vec...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm2vec-clone");
		indexToApp(ele, "test-cases/asm2vec/", "reindex-btn");
		searchExampleCode("Flow graph comparison.", "Full text alignment.");
	}

	@Test
	public void testAsm2VecComposition() throws Exception {
		log("Testing asm2VecComposition...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm2vec-clone");
		indexToApp(ele, "test-cases/asm2vec/", "reindex-btn");
		searchFile(
				KamResourceLoader
						.getFileThatWillNotInDistribution("test-cases/asm2vec/libz.so.1.2.11-gcc-g-O0-m32-fno-pic.bin"),
				"http://127.0.0.1:8571/userHome");
	}

	@Test
	public void testSym1n0() throws Exception {
		log("Testing sym1n0...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/sym1n0-clone");
		indexToApp(ele, "test-cases/sym1n0/", "index-btn");
		searchExampleCode("Flow graph comparison.", "Flow graph comparison (VEX).",
				"Flow graph comparison (syntax tree).", "Full text alignment (ASM).", "Full text alignment (VEX).",
				"Clone group alignment.");
	}

	@Test
	public void testChromium() throws Exception {
		log("Testing chrome indexing...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm-clone");
		indexToApp(ele, "test-cases/chrome-test/", "index-btn");
		searchExampleCode("Flow graph comparison.", "Full text alignment.");
	}
}
