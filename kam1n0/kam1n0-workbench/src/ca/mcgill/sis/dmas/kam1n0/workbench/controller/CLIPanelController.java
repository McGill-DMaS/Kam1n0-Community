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

import java.io.File;
import java.util.ArrayList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class CLIPanelController {

	@FXML
	TextArea console;

	MainApp app;

	Process process;

	volatile boolean startBrowsing = true; 

	@FXML
	private void initialize() {
	}

	@FXML
	public void handleClose(ActionEvent event) {

	}

	public void browse(MainApp app, File file) {
		this.app = app;
		this.startBrowsing = true;
		new Thread(() -> {
			//this.process = this.app.connector.browseCloneDataUnit(file, new Console(console));
			this.startBrowsing = false;
		}).start();

	}

	public void close() {
		if (this.process != null && this.startBrowsing == false) {
			this.process.destroyForcibly();
		}
	}

}
