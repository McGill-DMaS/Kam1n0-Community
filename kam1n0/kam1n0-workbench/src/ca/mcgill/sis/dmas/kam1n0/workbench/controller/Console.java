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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.Timer;
import java.util.TimerTask;

import javafx.scene.control.TextArea;

public class Console implements Consumer<String> {
	private List<String> buffer = new ArrayList<>();
	private TextArea ta;

	public Console(TextArea ta) {
		this(ta, 50000);
	}
 
	public Console(TextArea area, int bufferSize) {
		this.ta = area;
		Timer timer = new Timer();
		timer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() { 
				String content = "";
				synchronized (buffer) {
					if (buffer.size() < 1)
						return;
					StringBuilder builder = new StringBuilder();
					for (String line : buffer)
						builder.append(line).append(System.lineSeparator());
					content = builder.toString();
					buffer.clear();
				}
				synchronized (ta) {
					ta.appendText(content);
					int len = ta.getLength();
					if (len > bufferSize)
						ta.deleteText(0, len - bufferSize);
					ta.setScrollTop(Double.MAX_VALUE);
					ta.setScrollLeft(Double.MIN_VALUE); 
				}
			}
		}, (int)(0.5 * 1000), (int)(0.5 * 1000));
	}

	public void clear() {
		synchronized (ta) {
			ta.clear();
		}
		
	}

	@Override
	public void accept(String t) {
		synchronized (buffer) {
			buffer.add(t);
		}
	}

}