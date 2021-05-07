package ca.mcgill.sis.dmas.kam1n0;

import org.apache.commons.lang3.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import ca.mcgill.sis.dmas.env.Environment;
import ca.mcgill.sis.dmas.env.Environment.KamMode;
import ca.mcgill.sis.dmas.res.KamResourceLoader;
import java.awt.Desktop;
import java.net.URI;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SpringBootApplication
public class Application {

	private static Logger logger = LoggerFactory.getLogger(Application.class);
	private static Pattern mbRegex = Pattern.compile("([0-9]+)MB");
	private static ConfigurableApplicationContext appRef;

	public static void main(String... args) {
		boolean popup = System.getProperty("kam1n0.spring.popup", "true").equalsIgnoreCase("true");
		start(popup, args);
	}

	public static void start(boolean popup, String... args) {
		Environment.init(KamMode.server, args);
		String port = setServerProperty();
		appRef = SpringApplication.run(Application.class, args);

		// pop out browser after spring boot initialized;
		// so one does not need to remember to port.
		if (popup)
			openWebpage("http://127.0.0.1:" + port);
	}

	public static void stop() {
		if (appRef != null)
			appRef.stop();
	}

	public static String setServerProperty() {
		// logging ansi
		if (KamResourceLoader.useAnsi)
			System.setProperty("spring.output.ansi.enabled", "always");
		// logging path
		if (System.getProperty("kam1n0.data.logging.path") != null && !KamResourceLoader.runningInsideIDE) {
			System.setProperty("logging.path", System.getProperty("kam1n0.data.logging.path"));
			logger.info("Logging to {}", System.getProperty("logging.path"));
		}
		// web port
		String port = System.getProperty("kam1n0.web.port", "8571");
		System.setProperty("server.port", port);
		// web timeout
		String timeout = System.getProperty("kam1n0.web.session.timeout", "3600");
		System.setProperty("server.session.cookie.max-age", timeout);
		System.setProperty("server.session.timeout", timeout);
		// web cache
		if (KamResourceLoader.runningInsideIDE)
			System.setProperty("spring.thymeleaf.cache", "false");
		else
			System.setProperty("spring.thymeleaf.cache", "true");
		// web request size
		String maxRequestSize = System.getProperty("kam1n0.web.request.maxSize", "10MB");
		int sizeInByte = 10 * 1024 * 1024;
		Matcher matcher = mbRegex.matcher(maxRequestSize);
		if (matcher.find()) {
			int sizeInMb = Integer.parseInt(matcher.group(1));
			sizeInByte = sizeInMb * 1024 * 1024;
		} else {
			logger.error("Failed to parse {} as size in MB. Expected format {}. Setting to default 10MB",
					maxRequestSize, mbRegex.pattern());
			maxRequestSize = "10MB";
			sizeInByte = 10 * 1024 * 1024;
		}
		System.setProperty("spring.http.multipart.maxFileSize", maxRequestSize);
		System.setProperty("spring.http.multipart.maxRequestSize", maxRequestSize);
		System.setProperty("spring.servlet.multipart.max-file-size", maxRequestSize);
		System.setProperty("spring.servlet.multipart.max-request-size", maxRequestSize);
		System.setProperty("server.tomcat.max-http-post-size", Integer.toString(sizeInByte));
		System.setProperty("server.tomcat.max-http-form-post-size", Integer.toString(sizeInByte));

		return port;
	}

	public static void openWebpage(String url) {
		try {
			URI uri = (new URL(url)).toURI();
			Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
			if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
				try {
					desktop.browse(uri);
				} catch (Exception e) {
					logger.warn("Failed to popout browser..", e);
				}
			} else {
				Runtime runtime = Runtime.getRuntime();
				try {
					if (SystemUtils.IS_OS_WINDOWS)
						runtime.exec("rundll32 url.dll,FileProtocolHandler " + url);
					else if (SystemUtils.IS_OS_LINUX)
						runtime.exec("xdg-open " + url);
				} catch (Exception e) {
					logger.warn("Failed to popout browser..", e);
				}
			}
		} catch (Exception e) {
			logger.error("Failed to pop up browser.. Please go to the site {} mannually.", url);
		}

	}

}
