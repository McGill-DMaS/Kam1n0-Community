/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.kam1n0.workbench.controller;

import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import javax.imageio.ImageIO;

import ca.mcgill.sis.dmas.kam1n0.workbench.connector.Kam1n0Connector;
import ca.mcgill.sis.dmas.kam1n0.workbench.connector.SimpleLogger;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.WindowEvent;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.scene.effect.DropShadow;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;

import java.awt.AWTException;
import java.awt.MenuItem;

public class MainApp extends Application {

	public SimpleLogger logger;

	public Console console;

	public Kam1n0Connector connector;

	public Stage stage;

	@Override
	public void start(Stage stage) {
		try {
			this.stage = stage;
			InputStream url = getClass().getClassLoader().getResource("Picture2-32.png").openStream();
			Image image = new Image(url);
			stage.getIcons().add(image);
			createTrayIcon(stage);
			firstTime = true;
			Platform.setImplicitExit(false);
			URL fxParent = getClass().getResource("forms/MainWindow.fxml");
			FXMLLoader loader = new FXMLLoader();
			loader.setLocation(fxParent);
			Scene scene = new Scene( loader.load(), Color.TRANSPARENT);
			stage.setTitle("Kam1n0 Workbench");
			stage.setScene(scene);
			stage.initStyle(StageStyle.TRANSPARENT);
			int padding = 20;
			ResizeHelper.addResizeListener(stage, padding, 300, 450);
			stage.show();
			TextArea connectorTextArea = (TextArea) scene.lookup("#logger");
			TextArea consoleTextArea = (TextArea) scene.lookup("#console");
			logger = new SimpleLogger(connectorTextArea);
			console = new Console(consoleTextArea);

			File thisjar = new File(
					MainApp.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
			File KAM1N0_HOME;
			if (thisjar.getName().equals("classes")) {
				// running inside eclipse
				logger.info("Running inside eclipse detected.");
				KAM1N0_HOME = new File(
						thisjar.getParentFile().getParentFile().getParentFile().getAbsolutePath() + "/build-bins/");
			} else {
				KAM1N0_HOME = new File(thisjar.getParentFile().getAbsolutePath());
			}
			connector = new Kam1n0Connector(KAM1N0_HOME.getAbsolutePath(), logger, console);
			MainWindowController controller = loader.getController();
			controller.setApp(this, padding); 

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void stop() throws Exception {
		this.connector.cleanup();
		super.stop(); 
	}

	public static void main(String[] args) {
		launch(args);
	}

	private boolean firstTime;
	private TrayIcon trayIcon;

	public void close() {
		connector.cleanup();
		Platform.runLater(new Runnable() {
			@Override
			public void run() {
				System.exit(0);
			}
		});
	}

	public void show() {
		Platform.runLater(new Runnable() {
			@Override
			public void run() {
				stage.show();
			}
		});
	}

	public void createTrayIcon(final Stage stage) {
		if (SystemTray.isSupported()) {
			// get the SystemTray instance
			SystemTray tray = SystemTray.getSystemTray();
			// load an image
			java.awt.Image image = null;
			try {
				URL url = getClass().getClassLoader().getResource("Picture2.png");
				image = ImageIO.read(url);
			} catch (IOException ex) {
				System.out.println(ex);
			}

			stage.iconifiedProperty().addListener(new ChangeListener<Boolean>() {
				@Override
				public void changed(ObservableValue<? extends Boolean> prop, Boolean oldValue, Boolean newValue) {
					if (prop.getValue() && SystemTray.isSupported()) {
						Platform.runLater(new Runnable() {
							@Override
							public void run() {
								stage.setIconified(false);
								stage.hide();
								showProgramIsMinimizedMsg();
							}
						});
					}
				}
			});

			stage.setOnCloseRequest(new EventHandler<WindowEvent>() {
				@Override
				public void handle(WindowEvent t) {
					connector.cleanup();
					Platform.runLater(new Runnable() {
						@Override
						public void run() {
							System.exit(0);
						}
					});
				}
			});

			// create a popup menu
			PopupMenu popup = new PopupMenu();

			MenuItem showItem = new MenuItem("Show");
			showItem.addActionListener(ev->this.show());
			popup.add(showItem);

			MenuItem closeItem = new MenuItem("Close");
			closeItem.addActionListener(env -> this.close());
			popup.add(closeItem);
			// construct a TrayIcon
			trayIcon = new TrayIcon(image, "Kam1n0 Workbench", popup);
			// set the TrayIcon properties
			trayIcon.addActionListener(ev->this.show());

			try {
				tray.add(trayIcon);
			} catch (AWTException e) {
				System.err.println(e);
			}
		}
	}

	public void showProgramIsMinimizedMsg() {
		if (firstTime) {
			trayIcon.displayMessage("Kam1n0-workbench", "Kam1n0-workbench is minized here.", TrayIcon.MessageType.INFO);
			firstTime = false;
		}
	}

}
