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
package ca.mcgill.sis.dmas.env;

import java.io.File;
import java.io.IOException;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

public class SystemInfo {

	/**
	 * total physical/total jvm/total used by process
	 */
	public double[] memory = new double[3];

	/**
	 * total/used for the data directory
	 */
	public double[] ldb = new double[2];

	/**
	 * system load/jvm load
	 */
	public double[] cpu = new double[2];

	@SuppressWarnings("restriction")
	public SystemInfo() {
		int mb = 1024 * 1024;
		int gb = 1024 * 1024 * 1024;
		Runtime runtime = Runtime.getRuntime();

		com.sun.management.OperatingSystemMXBean os = (com.sun.management.OperatingSystemMXBean) java.lang.management.ManagementFactory
				.getOperatingSystemMXBean();
		memory[0] = os.getFreePhysicalMemorySize() / mb;
		memory[1] = runtime.totalMemory() / mb;
		memory[2] = (runtime.totalMemory() - runtime.freeMemory()) / mb;

		File file = new File(DmasApplication.STR_DATA_PATH);
		ldb[0] = file.getTotalSpace() / gb;
		ldb[1] = file.getFreeSpace() / gb;

		cpu[0] = os.getSystemCpuLoad();
		cpu[1] = os.getProcessCpuLoad();

	}

	@Override
	public String toString() {
		int mb = 1024 * 1024;
		int gb = 1024 * 1024 * 1024;
		return StringResources.format("m0:{} m1:{} m2:{} {}% used" , memory[0],
				memory[1], memory[2], StringResources.FORMAT_AR2D.format(memory[2]*1.0/memory[1]));
	}

}