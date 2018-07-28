package ca.mcgill.sis.dmas.env;

import org.slf4j.LoggerFactory;

import ca.mcgill.sis.dmas.res.KamResourceLoader;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.FileAppender;

public class LogbackConfig {

	public final static String pattern_color = "%gray(%d{HH:mm:ss.SSS}) %-10([%.7thread]) %highlight(%-5level) %-50(%cyan(%.35logger{35})) - %msg%n";
	public final static String pattern = "%d{HH:mm:ss.SSS} %-10([%.7thread]) %-5level %-50(%.35logger{35}) - %msg%n";

	public static void detachAllandLogToConsole() {
		LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

		ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<>();
		consoleAppender.setContext(loggerContext);
		consoleAppender.setName("console");
		if (KamResourceLoader.useAnsi)
			consoleAppender.setWithJansi(true);

		PatternLayoutEncoder encoder = new PatternLayoutEncoder();
		encoder.setContext(loggerContext);
		if (KamResourceLoader.useAnsi)
			encoder.setPattern(pattern_color);
		else
			encoder.setPattern(pattern);
		encoder.start();

		consoleAppender.setEncoder(encoder);
		consoleAppender.start();

		// attach the rolling file appender to the logger of your choice
		Logger logbackLogger = (Logger) loggerContext.getLogger("org.apache.spark");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.apache.cassandra");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("com.datastax");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("akka.");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.hyperic");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.spark_project.jetty");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.reflections");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.INFO);

		logbackLogger = (Logger) loggerContext.getLogger("ROOT");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(consoleAppender);
		logbackLogger.setLevel(Level.INFO);

	}

	public static void logToFile(String file) {
		LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();

		FileAppender<ILoggingEvent> fileAppender = new FileAppender<ILoggingEvent>();
		fileAppender.setFile(file);
		fileAppender.setContext(loggerContext);

		PatternLayoutEncoder encoder = new PatternLayoutEncoder();
		encoder.setContext(loggerContext);
		encoder.setPattern(pattern);
		encoder.start();

		fileAppender.setEncoder(encoder);
		fileAppender.start();

		// attach the rolling file appender to the logger of your choice
		Logger logbackLogger = (Logger) loggerContext.getLogger("org.apache.spark");
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.apache.cassandra");
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("com.datastax");
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("akka.");
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.hyperic");
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.spark_project.jetty");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.WARN);

		logbackLogger = (Logger) loggerContext.getLogger("org.reflections");
		logbackLogger.detachAndStopAllAppenders();
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.INFO);

		logbackLogger = (Logger) loggerContext.getLogger("ROOT");
		logbackLogger.addAppender(fileAppender);
		logbackLogger.setLevel(Level.INFO);

	}

}
