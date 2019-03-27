package ca.mcgill.sis.dmas.kam1n0.app;

import static org.junit.Assert.*;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.logging.LogType;
import org.openqa.selenium.support.ui.Select;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.res.KamResourceLoader;
import static ca.mcgill.sis.dmas.kam1n0.app.UITestUtils.log;

public class UITest {
	private static ChromeDriver driver;
	WebElement element;
	List<String> errorStrings = Arrays.asList("SyntaxError", "EvalError", "ReferenceError", "RangeError", "TypeError",
			"URIError");

	@BeforeClass
	public static void prepareServerAndBrowser() throws Exception {

		UITestUtils.StartServer();
		// download from http://chromedriver.chromium.org/
		// need to set webdriver.chrome.driver in env vars
		String envp = System.getenv().get("webdriver.chrome.driver");
		System.setProperty("webdriver.chrome.driver", envp);
        ChromeOptions options = new ChromeOptions();
		options.addArguments("--window-size=1920,1080");
		options.setExperimentalOption("useAutomationExtension", false);
		options.addArguments("--start-maximized");
		driver = new ChromeDriver(options);
		driver.manage().timeouts().implicitlyWait(10, TimeUnit.SECONDS);

		Thread.sleep(3*1000 * 60); // sleep for 60 seconds (take a rest).
	}

	@AfterClass
	public static void cleanUp() throws Exception {
		log("Cleaning up...");
		if (driver != null)
			driver.quit();
		UITestUtils.cleanUp();

	}

	public void assertNoJSError() {
		List<LogEntry> anyErr = driver.manage().logs().get(LogType.BROWSER).getAll().stream()
				.filter(lg -> errorStrings.stream().filter(err -> lg.getMessage().contains(err)).findAny().isPresent())
				.collect(Collectors.toList());
		if (anyErr.size() > 0)
			log("JS Errors {}", anyErr);
		assertFalse(anyErr.size() > 0);
	}

	public void register() throws Exception {
		log("Testing register...");
		driver.get("http://127.0.0.1:8571/register");
		driver.findElement(By.id("username")).sendKeys("admin");
		driver.findElement(By.id("email")).sendKeys("admin@dmas.com");
		driver.findElement(By.id("pw")).sendKeys("admin");
		driver.findElement(By.id("aggreeTLicense1")).click();
		driver.findElement(By.tagName("button")).click();
		String response = driver.findElement(By.tagName("strong")).getText().trim().toLowerCase();
		assertEquals(response, "success");
	}

	public void login() throws Exception {
		log("Testing login...");
		driver.get("http://127.0.0.1:8571/login");
		driver.findElement(By.id("username")).sendKeys("admin");
		driver.findElement(By.id("password")).sendKeys("admin");
		driver.findElement(By.tagName("button")).click();
		Thread.sleep(3*5000); // sleep for 5s
		String url = driver.getCurrentUrl();
		assertTrue(url.endsWith("/userHome"));
        log("{}", url);
		driver.executeScript("$(\"li.dropdown > a\").click()");
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
		driver.findElement(By.id("title")).sendKeys(identifier + "_title");
		driver.findElement(By.id("description")).sendKeys(identifier + "_desp");
		driver.findElement(By.id("btn_submit")).click();
		Thread.sleep(3*5000);
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
		Thread.sleep(3*5000);
		log("Current URL {}", driver.getCurrentUrl());
		assertTrue(driver.getCurrentUrl().endsWith("/home"));

		for (File bin : bins) {
			driver.get(driver.getCurrentUrl());
			// driver.findElement(By.cssSelector("a[href='#settings']")).click();
			driver.executeScript("$(\"a[href='#settings']\").click()");
			WebElement input = driver.findElement(By.id("index-upload-input"));
			WebElement btn = driver.findElement(By.id(submit_btn_id));
			input.sendKeys(bin.getAbsolutePath());
			btn.click();
			Thread.sleep(3*5000);
			boolean error = false;
			do {
				List<WebElement> prgs = driver.findElementsByCssSelector("div.progress.active");
				error = driver.findElementsByCssSelector("span.progress-label").stream()
						.filter(sp -> sp.getText().toLowerCase().contains("exception")).findAny().isPresent();
				Thread.sleep(3*1000);
				if (prgs.size() == 0 || error)
					break;
			} while (true);
			assertFalse(error);
		}

	}

	public void searchFile(File file, String userHomeURL) throws Exception {
		log("Current URL {}", driver.getCurrentUrl());
		assertTrue(driver.getCurrentUrl().endsWith("/home"));

		driver.get(driver.getCurrentUrl());
		// driver.findElement(By.cssSelector("a[href='#messages']")).click();
		driver.executeScript("$(\"a[href='#messages']\").click()");
		WebElement input = driver.findElement(By.id("search-upload-input"));
		WebElement btn = driver.findElement(By.id("search-btn-binary"));
		input.sendKeys(file.getAbsolutePath());
		btn.click();
		Thread.sleep(3*5000);
		boolean error = false;
		do {
			List<WebElement> prgs = driver.findElementsByCssSelector("div.progress.active");
			error = driver.findElementsByCssSelector("span.progress-label").stream()
					.filter(sp -> sp.getText().toLowerCase().contains("exception")).findAny().isPresent();
			Thread.sleep(3*500);
			if (prgs.size() == 0 || error)
				break;
		} while (true);
		assertFalse(error);

		driver.get(userHomeURL);
		assertTrue(driver.getCurrentUrl().endsWith("/userHome"));

		WebElement open = driver.findElementByCssSelector(".href-file-open");
		assertTrue(open.getAttribute("disabled") == null);
		open.click();
		HashSet<String> handlers = new HashSet<>(driver.getWindowHandles());
		assertTrue(handlers.size() == 2);
		String original = driver.getWindowHandle();
		handlers.remove(original);
		driver.switchTo().window(handlers.stream().findAny().get());
		Thread.sleep(3*5000);
		List<WebElement> cards = driver.findElementsByCssSelector(".card");
		log("{} cards", cards.size());
		assertTrue(cards.size() > 0);
		Thread.sleep(3*5000);
		// driver.findElement(By.cssSelector("a[href='#details']")).click();
		driver.executeScript("$(\"a[href='#details']\").click()");
		// driver.executeScript("$(\"span[text()=\"adler32_z\"]).click()");
		// driver.findElementByCssSelector("span[text() = \"adler32_z\"]").click();
		driver.executeScript("$(\"span:contains('adler32_z')\").click()");
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
		// driver.findElement(By.cssSelector("a[href='#profile']")).click();
		WebElement btn = driver.findElement(By.id("func-clone-btn "));
		Select dropdown = new Select(driver.findElement(By.id("clone-func-example")));
		dropdown.selectByIndex(1);
		btn.click();

		Thread.sleep(3*20000);
		String parentWindowHandler = driver.getWindowHandle(); // Store your parent window
		Set<String> handles = new HashSet<>(driver.getWindowHandles());
		handles.remove(parentWindowHandler);
		for (String subWindowHandler : handles) {
			driver.switchTo().window(subWindowHandler);
			String url = driver.getCurrentUrl();
			log("URL {}", url);
			if (url.endsWith("/search_func/")) {
				assertNoJSError();
				log("Searching no JS error. But over time limit 10s");
				throw new Exception("Search timeout error.");
			} else if (url.endsWith("/search_func_render")) {
				driver.executeScript("$(\"button[title='Open All']\").click()");
				driver.findElement(By.cssSelector("button[title='Open All']")).click();
				assertNoJSError();
				for (String view : views) {
					log("going to view {}", view);
					driver.executeScript("$(\"span[title='" + view + "']\").slice(0,3).click()");
					// driver.findElement(By.cssSelector("span[title='" + view + "']")).click();
					driver.switchTo().window(subWindowHandler);
				}

				Set<String> viewHandles = new HashSet<>(driver.getWindowHandles());
				viewHandles.remove(parentWindowHandler);
				viewHandles.remove(subWindowHandler);
				for (String viewWindowHandler : viewHandles) {
					WebDriver win = driver.switchTo().window(viewWindowHandler);
					log("checking view {}", win.getTitle());
					Thread.sleep(3*20000);
					assertNoJSError();
					driver.close();
				}

				driver.switchTo().window(subWindowHandler);
				driver.close();
			}
		}

		driver.switchTo().window(parentWindowHandler);

	}

	public void testDisassemblyFactory() throws Exception {
		log("Testing disassembly factory...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm-clone");
		indexToApp(ele, "test-cases/disassembly_test_case/", "index-btn");
	}

	public void testAsmClone() throws Exception {
		log("Testing asm-clone...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm-clone");
		indexToApp(ele, "test-cases/asmclone/", "index-btn");
		searchExampleCode("Flow graph comparison.", "Full text alignment.", "Clone group alignment.");
	}

	public void testAsm2Vec() throws Exception {
		log("Testing asm2vec...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm2vec-clone");
		indexToApp(ele, "test-cases/asm2vec/", "reindex-btn");
		searchExampleCode("Flow graph comparison.", "Full text alignment.");
	}

	public void testAsm2VecComposition() throws Exception {
		log("Testing asm2vec...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm2vec-clone");
		indexToApp(ele, "test-cases/asm2vec/", "reindex-btn");
		searchFile(
				KamResourceLoader
						.getFileThatWillNotInDistribution("test-cases/asm2vec/libz.so.1.2.11-gcc-g-O0-m32-fno-pic.bin"),
				"http://127.0.0.1:8571/userHome");
	}

	public void testSym1n0() throws Exception {
		log("Testing sym1n0...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/sym1n0-clone");
		indexToApp(ele, "test-cases/sym1n0/", "index-btn");
		searchExampleCode("Flow graph comparison.", "Flow graph comparison (VEX).",
				"Flow graph comparison (syntax tree).", "Full text alignment (ASM).", "Full text alignment (VEX).",
				"Clone group alignment.");
	}

	public void testChromium() throws Exception {
		log("Testing chrome indexing...");
		driver.get("http://127.0.0.1:8571/userHome");
		WebElement ele = createApp("/asm-clone");
		indexToApp(ele, "test-cases/chrome-test/", "index-btn");
		searchExampleCode("Flow graph comparison.", "Full text alignment.");
	}

	@Test
	public void test_all_in_sequence() throws Exception {
		register();
		login();
		testAsm2VecComposition();
		testDisassemblyFactory();
		testAsmClone();
		testAsm2Vec();
		testSym1n0();
		testChromium();
	}

}
