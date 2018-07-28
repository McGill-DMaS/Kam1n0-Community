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
package ca.mcgill.sis.dmas.kam1n0.workbench.connector;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.function.Consumer;

import javafx.application.Platform;
import javafx.scene.control.TextArea;

public class SimpleLogger {

	public synchronized void info(String message) {
		if (consumer != null)
			consumer.accept(timeString() + " [INFO] " + message+ "\n");
	}

	public synchronized void error(String message) {
		if (consumer != null) 
			consumer.accept(timeString() + " [INFO] " + message + "\n");
	}

	Consumer<String> consumer;
 
	public SimpleLogger(TextArea area) {
		this.consumer = str -> {
			Platform.runLater(new Runnable() {
				public void run() {
					area.appendText(str);
					area.setScrollTop(Double.MAX_VALUE);
					area.setScrollLeft(Double.MIN_VALUE); 
				}
			});
		};
	}

	public static String timeString() {
		return FORMAT_TIME.format(new Date());
	}

	public static SimpleDateFormat FORMAT_TIME = new SimpleDateFormat("MM-dd-HH:mm:ss");
}
