/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kam1n0;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import javax.swing.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;
import resources.ResourceManager;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "Kam1n0 Plugin",
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class kam1n0Plugin extends ProgramPlugin {

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public kam1n0Plugin(PluginTool tool) {
		super(tool, true, true);
		buildPanel();
		buildConfPanel();
		createIndexAction();
		createSearchAction();
		createConfigAction();

	}

	@Override
	public void init() {
		super.init();

	}



	private JPanel panel;
	private ConfigDialog dialog;
	private DockingAction actionIndex;
	private DockingAction actionSearch;
	private DockingAction actionConfig;
	private Program program;
	private static Path kam1n0Home = Paths.get(System.getProperty("user.home"), "kam1n0");
	private static Path configureFile = Paths.get(System.getProperty("user.home"), "kam1n0", "ghidra.properties");
	private static Path scriptFile = Paths.get(System.getProperty("user.home"), "kam1n0", "utilities",
			"RequestPage.py");
	private static Path utilityHome = Paths.get(System.getProperty("user.home"), "kam1n0", "utilities");

	public static class ConfigDialog extends DialogComponentProvider {

		private JLabel labelUsername = new JLabel("Enter username: ");
		private JLabel labelPassword = new JLabel("Enter password: ");
		private JLabel labelURL = new JLabel("Enter application plugin URL: ");
		private JTextField textUsername = new JTextField(20);
		private JTextField textURL = new JTextField(50);
		private JPasswordField fieldPassword = new JPasswordField(20);
		private JButton buttonLogin = new JButton("Save");
		private CookieManager cookieManager = new CookieManager();
		public Properties prop;
		private String sessionId;

		protected ConfigDialog(String title) {
			super(title);

			JPanel panel = new JPanel(new GridBagLayout());

			GridBagConstraints constraints = new GridBagConstraints();
			constraints.anchor = GridBagConstraints.WEST;
			constraints.insets = new Insets(10, 10, 10, 10);

			// add components to the panel
			constraints.gridx = 0;
			constraints.gridy = 0;
			panel.add(labelURL, constraints);

			constraints.gridx = 1;
			panel.add(textURL, constraints);

			constraints.gridx = 0;
			constraints.gridy = 1;
			panel.add(labelUsername, constraints);

			constraints.gridx = 1;
			panel.add(textUsername, constraints);

			constraints.gridx = 0;
			constraints.gridy = 2;
			panel.add(labelPassword, constraints);

			constraints.gridx = 1;
			panel.add(fieldPassword, constraints);

			constraints.gridx = 0;
			constraints.gridy = 3;
			constraints.gridwidth = 2;
			constraints.anchor = GridBagConstraints.CENTER;
			panel.add(buttonLogin, constraints);

			// set border for the panel
			panel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Connection Info"));

			addWorkPanel(panel);

			if (!kam1n0Home.toFile().exists()) {
				kam1n0Home.toFile().mkdirs();
			}
			if(!utilityHome.toFile().exists()) {
				try {
					(new ResourceCopy()).copyResourcesToDir(kam1n0Home.toFile(), true,
							"utilities/RequestPage.py",
							"utilities/resources/jquery.min.js",
							"utilities/resources/operations.html",
							"utilities/resources/js.cookie.js");
//					ResourcesUtils.copyFromJar ("/utilities", utilityHome);
				} catch (Exception e1) {
					e1.printStackTrace();
				} 
			}

			if (configureFile.toFile().exists()) {
				try (InputStream input = new FileInputStream(configureFile.toFile())) {
					prop = new Properties();
					prop.load(input);
					System.out.println(prop);
					this.textUsername.setText(prop.getProperty("name"));
					this.textURL.setText(prop.getProperty("url"));
					this.fieldPassword.setText(prop.getProperty("password"));
				} catch (IOException ex) {
					ex.printStackTrace();
					prop = null;
				}
			}

			buttonLogin.addActionListener(e -> {
				prop = new Properties();
				prop.setProperty("name", this.textUsername.getText());
				prop.setProperty("url", this.textURL.getText());
				prop.setProperty("password", new String(this.fieldPassword.getPassword()));

				try (OutputStream output = new FileOutputStream(configureFile.toFile())) {
					prop.store(output, null);
					System.out.println(prop);
				} catch (IOException io) {
					io.printStackTrace();
				}
				this.close();
			});
		}

		public String getSessionID() {

			if (this.sessionId != null)
				return this.sessionId;

			try {
				
				CookieHandler.setDefault(cookieManager);

				String urlParameters = "username=" + prop.getProperty("name") + "&password="
						+ prop.getProperty("password");
				System.out.println(urlParameters);
				byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);
				int postDataLength = postData.length;

				URL url_app = new URL(prop.getProperty("url"));
				int port = url_app.getPort();
				String loginAddress = url_app.getProtocol() + "://" + url_app.getHost();
				if (port > 0) {
					loginAddress += ":" + port;
				}
				URL url = new URL(loginAddress + "/login");
				System.out.println(url);
				HttpURLConnection conn = (HttpURLConnection) url.openConnection();
				conn.setInstanceFollowRedirects(false);
				conn.setDoOutput(true);
				conn.setInstanceFollowRedirects(false);
				conn.setRequestMethod("POST");
				conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
				conn.setRequestProperty("charset", "utf-8");
				conn.setRequestProperty("User-agent", "Kam1n0-py/2.0.0");
				conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));
				conn.setUseCaches(false);
				try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
					wr.write(postData);
				}

				BufferedReader br = null;

				br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
				String strCurrentLine;
				while ((strCurrentLine = br.readLine()) != null) {
					System.out.println(strCurrentLine);
				}
				System.out.println(conn.getResponseCode());
				System.out.println(conn.getResponseMessage());
				String location = conn.getHeaderField("Location");
				System.out.println(location);

				if (location.toString().contains("userHome")) {
					List<HttpCookie> cookies = cookieManager.getCookieStore().getCookies();
					for (HttpCookie cookie : cookies) {
						System.out.println(cookie.getDomain() + ":" + cookie);
						if (cookie.toString().contains("JSESSIONID=")) {
							this.sessionId = cookie.toString().replace("JSESSIONID=", "");
						}
					}
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
			return this.sessionId;
		}

	}

	// Customize GUI
	private void buildPanel() {
		panel = new JPanel(new BorderLayout());
		JTextArea textArea = new JTextArea(5, 25);
		textArea.setEditable(true);
		panel.add(new JScrollPane(textArea));
	}

	private void buildConfPanel() {
		dialog = new ConfigDialog("Kam1n0 Connections");
	}

	// TODO: Customize actions
	private void createIndexAction() {
		actionIndex = new DockingAction("Index All", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				if (dialog.prop == null) {
					tool.showDialog(dialog);
				}

				Model model = ModelExtractor.extract(program);
				// initialize session if not yet
				dialog.getSessionID();
				ObjectMapper mapper = new ObjectMapper();
				try {
					String content = mapper.writeValueAsString(model);
					CookieHandler.setDefault(dialog.cookieManager);
					content = URLEncoder.encode(content, StandardCharsets.UTF_8);

					String urlParameters = "files=" + content + "&files=";
					byte[] postData = urlParameters.getBytes(StandardCharsets.UTF_8);
					int postDataLength = postData.length;

					URL url = new URL(dialog.prop.getProperty("url")+"push_bin");
					System.out.println(url);
					HttpURLConnection conn = (HttpURLConnection) url.openConnection();
					conn.setInstanceFollowRedirects(false);
					conn.setDoOutput(true);
					conn.setInstanceFollowRedirects(false);
					conn.setRequestMethod("POST");
					conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
					conn.setRequestProperty("charset", "utf-8");
					conn.setRequestProperty("User-agent", "Kam1n0-py/2.0.0");
					conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));
					conn.setUseCaches(false);
					try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
						wr.write(postData);
					}

					BufferedReader br = null;

					br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
					String strCurrentLine;
					while ((strCurrentLine = br.readLine()) != null) {
						System.out.println(strCurrentLine);
					}
					System.out.println(conn.getResponseCode());
					System.out.println(conn.getResponseMessage());
					String location = conn.getHeaderField("Location");
					System.out.println(location);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				Msg.showInfo(getClass(), panel, "Kam1n0 Plugin", "Indexing Finished!");
			}
		};

		actionIndex.setEnabled(true);
		String infoGroup = "Kam1n0";
		ImageIcon iconImage = ResourceManager.loadImage("images/upload_multiple.png");
		actionIndex
				.setMenuBarData(new MenuData(new String[] { "Kam1n0", "Index all functions." }, iconImage, infoGroup));
		actionIndex.setPopupMenuData(new MenuData(new String[] { "Index all functions." }, iconImage, infoGroup));
		actionIndex.setToolBarData(new ToolBarData(iconImage, infoGroup));
		actionIndex.setDescription("Index all functions.");
		actionIndex.setHelpLocation(new HelpLocation("SampleHelpTopic", "KS_Index_All"));
		tool.addAction(actionIndex);

	}

	private void createSearchAction() {
		actionSearch = new DockingAction("Search current", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				if (dialog.prop == null) {
					tool.showDialog(dialog);
				}

				ProgramLocation loc = getProgramLocation();
				System.out.println(loc);

				Model model = ModelExtractor.extract(program, loc);

				ObjectMapper mapper = new ObjectMapper();
				try {
					String data = mapper.writeValueAsString(model);
					System.out.println(data);
					
					if (model == null) {
						Msg.showInfo(getClass(), panel, "Kam1n0 Plugin", "There is no function here.");
					} else {

						String[] cmd = new String[] { "python", scriptFile.toAbsolutePath().toString(),
							dialog.prop.getProperty("url")+"search_func", "post", dialog.getSessionID(),
//								"http:\\www.google.com", "get", dialog.getSessionID(),
								};
						Process p = Runtime.getRuntime().exec(cmd);

						data = "{\"param\": {}, \"external\": " + data + "}";
						
						System.out.println(data);

						OutputStream stdIn = p.getOutputStream();
						try (DataOutputStream wr = new DataOutputStream(stdIn)) {
							wr.write(data.getBytes(StandardCharsets.UTF_8));
						}

						try (BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
							String line;

							while ((line = input.readLine()) != null) {
								System.out.println(line);
							}
						}
						try (BufferedReader input = new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
							String line;

							while ((line = input.readLine()) != null) {
								System.out.println(line);
							}
						}

					}

				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

//				Msg.showInfo(getClass(), panel, "Kam1n0 Plugin", "Search Finished!");
			}
		};

		actionSearch.setEnabled(true);
		String infoGroup = "Kam1n0";
		ImageIcon iconImage = ResourceManager.loadImage("images/search.png");
		actionSearch.setMenuBarData(
				new MenuData(new String[] { "Kam1n0", "Search current function." }, iconImage, infoGroup));
		actionSearch.setPopupMenuData(new MenuData(new String[] { "Search current function." }, iconImage, infoGroup));
		actionSearch.setToolBarData(new ToolBarData(iconImage, infoGroup));
		actionSearch.setDescription("Search current function.");
		actionSearch.setHelpLocation(new HelpLocation("SampleHelpTopic", "KS_Search"));
		tool.addAction(actionSearch);
	}

	private void createConfigAction() {
		actionConfig = new DockingAction("Configure connection.", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				tool.showDialog(dialog);
			}
		};

		actionConfig.setEnabled(true);
		String infoGroup = "Kam1n0";
		ImageIcon iconImage = ResourceManager.loadImage("images/setting-cnn.png");
		actionConfig
				.setMenuBarData(new MenuData(new String[] { "Kam1n0", "Configure connection." }, iconImage, infoGroup));
		actionConfig.setPopupMenuData(new MenuData(new String[] { "Configure connection." }, iconImage, infoGroup));
		actionConfig.setToolBarData(new ToolBarData(iconImage, infoGroup));
		actionConfig.setDescription("Configure connections.");
		actionConfig.setHelpLocation(new HelpLocation("SampleHelpTopic", "KS_Config"));
		tool.addAction(actionConfig);
	}

	@Override
	protected void programActivated(Program activatedProgram) {
		actionIndex.setEnabled(true);
		actionSearch.setEnabled(true);
		this.program = activatedProgram;
	}

	@Override
	protected void programDeactivated(Program deactivatedProgram) {
		if (this.program == deactivatedProgram) {
			actionIndex.setEnabled(false);
			actionSearch.setEnabled(true);
			this.program = null;
		}
	}

}
