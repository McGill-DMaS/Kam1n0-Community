package ca.mcgill.sis.dmas.env;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.cassandra.thrift.Cassandra.AsyncProcessor.set_cql_version;

import ca.mcgill.sis.dmas.env.WinUtils.WindowsReqistry;

public class WinUtils {

	/**
	 * Modifed from
	 * https://stackoverflow.com/questions/62289/read-write-to-windows-registry-using-java
	 */
	public static class WindowsReqistry {

		private static Pattern reg = Pattern
				.compile("    \\(Default\\)    (REG_SZ|REG_MULTI_SZ|REG_EXPAND_SZ|REG_BINARY|REG_DWORD|REG_QWORD)[\\s]*(.+)");

		/**
		 * 
		 * @param location
		 *            path in the registry
		 * @param key
		 *            registry key
		 * @return registry value or null if not found
		 */
		public static final String readRegistry(String location) {
			try {
				// Run reg query, then read output with StreamReader (internal class)
				Process process = Runtime.getRuntime().exec("reg query " + '"' + location + "\"");

				StreamReader reader = new StreamReader(process.getInputStream());
				reader.start();
				process.waitFor();
				reader.join();
				String output = reader.getResult();

				Matcher matcher = reg.matcher(output);
				if (!matcher.find())
					return null;

				return matcher.group(2);
			} catch (Exception e) {
				return null;
			}

		}

		static class StreamReader extends Thread {
			private InputStream is;
			private StringWriter sw = new StringWriter();

			public StreamReader(InputStream is) {
				this.is = is;
			}

			public void run() {
				try {
					int c;
					while ((c = is.read()) != -1)
						sw.write(c);
				} catch (IOException e) {
				}
			}

			public String getResult() {
				return sw.toString();
			}
		}

		public static void main(String[] args) {

			String value = WindowsReqistry
					.readRegistry("HKLM\\SOFTWARE\\Classes\\IDApro.Database64\\shell\\open\\command");
			value = value.split("\"")[1];
			if (value.endsWith("ida64.exe"))
				value.replace("ida64.exe", "");
			System.out.println(value);
		}
	}
}
