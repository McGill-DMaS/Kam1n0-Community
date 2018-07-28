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
package ca.mcgill.sis.dmas.kam1n0.cli.evaluator;

public class ROCPNPoint implements Comparable {

	/**
	 * 
	 * @param tps true positives rate
	 * @param fps false positive rate
	 */
	public ROCPNPoint(double tps, double fps) {
		if (tps < 0.0D || fps < 0.0D) {
			pos = 0.0D;
			neg = 0.0D;
			System.err.println((new StringBuilder()).append("ERROR: ")
					.append(tps).append(",").append(fps).append(" - Defaulting ")
					.append("PNPoint to 0,0").toString());
		} else {
			pos = tps;
			neg = fps;
		}
	}

	/**
	 * 
	 * @return number of true positives
	 */
	public double getPos() {
		return pos;
	}

	/**
	 * 
	 * @return number of false positives
	 */
	public double getNeg() {
		return neg;
	}

	/**
	 * sorted by tp then fp;
	 */
	public int compareTo(Object obj) {
		if (obj instanceof ROCPNPoint) {
			ROCPNPoint pnpoint = (ROCPNPoint) obj;
			if (pos - pnpoint.pos > 0.0D)
				return 1;
			if (pos - pnpoint.pos < 0.0D)
				return -1;
			if (neg - pnpoint.neg > 0.0D)
				return 1;
			return neg - pnpoint.neg >= 0.0D ? 0 : -1;
		} else {
			return -1;
		}
	}

	public boolean equals(Object obj) {
		if (obj instanceof ROCPNPoint) {
			ROCPNPoint pnpoint = (ROCPNPoint) obj;
			if (Math.abs(pos - pnpoint.pos) > 0.001D)
				return false;
			return Math.abs(neg - pnpoint.neg) <= 0.001D;
		} else {
			return false;
		}
	}

	public String toString() {
		String s = "";
		s = (new StringBuilder()).append(s).append("(").append(pos).append(",")
				.append(neg).append(")").toString();
		return s;
	}

	private double pos;
	private double neg;
}
