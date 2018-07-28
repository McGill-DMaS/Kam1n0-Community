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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Vector;


public class ROCConfusion extends Vector<ROCPNPoint> {

	/**
	 * 
	 */
	private static final long serialVersionUID = -1101628822835701451L;

	/**
	 * 
	 * @param total
	 *            positive samples
	 * @param d1
	 *            total negative samples
	 */
	public ROCConfusion(double positives, double negatives) {
		if (positives < 1.0D || negatives < 1.0D) {
			totPos = 1.0D;
			totNeg = 1.0D;
			System.err.println((new StringBuilder()).append("ERROR: ")
					.append(positives).append(",").append(negatives)
					.append(" - ").append("Defaulting Confusion to 1,1")
					.toString());
		} else {
			totPos = positives;
			totNeg = negatives;
		}
	}

	/**
	 * 
	 * @param recall
	 *            recall
	 * @param precision
	 *            precision
	 * @throws NumberFormatException
	 */
	public void addPRPoint(double recall, double precision)
			throws NumberFormatException {
		if (recall > 1.0D || recall < 0.0D || precision > 1.0D
				|| precision < 0.0D)
			throw new NumberFormatException();
		double tps = recall * totPos; // true positives
		double fps = tps / precision * (1 - precision); // false positives
		ROCPNPoint pnpoint = new ROCPNPoint(tps, fps);
		if (!contains(pnpoint))
			add(pnpoint);
	}

	/**
	 * 
	 * @param d
	 *            true positive rate
	 * @param d1
	 *            palse positive rate
	 * @throws NumberFormatException
	 */
	public void addROCPoint(double d, double d1) throws NumberFormatException {
		if (d > 1.0D || d < 0.0D || d1 > 1.0D || d1 < 0.0D)
			throw new NumberFormatException();
		double d2 = d1 * totPos;
		double d3 = d * totNeg;
		ROCPNPoint pnpoint = new ROCPNPoint(d2, d3);
		if (!contains(pnpoint))
			add(pnpoint);
	}

	/**
	 * 
	 * @param d
	 *            true positives
	 * @param d1
	 *            false positives
	 * @throws NumberFormatException
	 */
	public void addPoint(double d, double d1) throws NumberFormatException {
		if (d < 0.0D || d > totPos || d1 < 0.0D || d1 > totNeg)
			throw new NumberFormatException();
		ROCPNPoint pnpoint = new ROCPNPoint(d, d1);
		if (!contains(pnpoint))
			add(pnpoint);
	}

	public void sort() {
		if (size() == 0) {
			System.err.println("ERROR: No data to sort....");
			return;
		}
		ROCPNPoint apnpoint[] = new ROCPNPoint[size()];
		int i = 0;
		for (; size() > 0; removeElementAt(0))
			apnpoint[i++] = (ROCPNPoint) elementAt(0);

		Arrays.sort(apnpoint);
		for (int j = 0; j < apnpoint.length; j++)
			add(apnpoint[j]);

		ROCPNPoint pnpoint;
		for (pnpoint = (ROCPNPoint) elementAt(0); pnpoint.getPos() < 0.001D
				&& pnpoint.getPos() > -0.001D; pnpoint = (ROCPNPoint) elementAt(0))
			removeElementAt(0);

		double d = pnpoint.getNeg() / pnpoint.getPos();
		ROCPNPoint pnpoint1 = new ROCPNPoint(1.0D, d);
		if (!contains(pnpoint1) && pnpoint.getPos() > 1.0D)
			insertElementAt(pnpoint1, 0);
		pnpoint1 = new ROCPNPoint(totPos, totNeg);
		if (!contains(pnpoint1))
			add(pnpoint1);
	}

	public void interpolate() {
		if (size() == 0) {
			System.err.println("ERROR: No data to interpolate....");
			return;
		}
		for (int i = 0; i < size() - 1; i++) {
			ROCPNPoint pnpoint = (ROCPNPoint) elementAt(i);
			ROCPNPoint pnpoint1 = (ROCPNPoint) elementAt(i + 1);
			double d = pnpoint1.getPos() - pnpoint.getPos();
			double d1 = pnpoint1.getNeg() - pnpoint.getNeg();
			double d2 = d1 / d;
			double d3 = pnpoint.getPos();
			double d4 = pnpoint.getNeg();
			ROCPNPoint pnpoint2;
			for (; Math.abs(pnpoint.getPos() - pnpoint1.getPos()) > 1.0009999999999999D; pnpoint = pnpoint2) {
				double d5 = d4 + ((pnpoint.getPos() - d3) + 1.0D) * d2;
				pnpoint2 = new ROCPNPoint(pnpoint.getPos() + 1.0D, d5);
				insertElementAt(pnpoint2, ++i);
			}

		}

	}

	public double calculateAUCPR(double d) {
		if (d < 0.0D || d > 1.0D) {
			System.err
					.println("ERROR: invalid minRecall, must be between 0 and 1 - returning 0");
			return 0.0D;
		}
		if (size() == 0) {
			System.err.println("ERROR: No data to calculate....");
			return 0.0D;
		}
		double d1 = d * totPos;
		int i = 0;
		ROCPNPoint pnpoint = (ROCPNPoint) elementAt(i);
		ROCPNPoint pnpoint2 = null;
		try {
			for (; pnpoint.getPos() < d1; pnpoint = (ROCPNPoint) elementAt(++i))
				pnpoint2 = pnpoint;

		} catch (ArrayIndexOutOfBoundsException arrayindexoutofboundsexception) {
			System.out.println("ERROR: minRecall out of bounds - exiting...");
			System.exit(-1);
		}
		double d2 = (pnpoint.getPos() - d1) / totPos;
		double d3 = pnpoint.getPos() / (pnpoint.getPos() + pnpoint.getNeg());
		double d4 = d2 * d3;
		if (pnpoint2 != null) {
			double d5 = pnpoint.getPos() / totPos - pnpoint2.getPos() / totPos;
			double d6 = pnpoint.getPos()
					/ (pnpoint.getPos() + pnpoint.getNeg()) - pnpoint2.getPos()
					/ (pnpoint2.getPos() + pnpoint2.getNeg());
			double d8 = d6 / d5;
			double d10 = pnpoint2.getPos()
					/ (pnpoint2.getPos() + pnpoint2.getNeg())
					+ (d8 * (d1 - pnpoint2.getPos())) / totPos;
			double d12 = 0.5D * d2 * (d10 - d3);
			d4 += d12;
		}
		d2 = pnpoint.getPos() / totPos;
		for (int j = i + 1; j < size(); j++) {
			ROCPNPoint pnpoint3 = (ROCPNPoint) elementAt(j);
			double d7 = pnpoint3.getPos() / totPos;
			double d9 = pnpoint3.getPos()
					/ (pnpoint3.getPos() + pnpoint3.getNeg());
			double d11 = (d7 - d2) * d9;
			double d13 = 0.5D * (d7 - d2) * (d3 - d9);
			d4 += d11 + d13;
			ROCPNPoint pnpoint1 = pnpoint3;
			d2 = d7;
			d3 = d9;
		}

		System.out.println((new StringBuilder())
				.append("Area Under the Curve for Precision - Recall is ")
				.append(d4).toString());
		return d4;
	}

	public double calculateAUCROC() {
		if (size() == 0) {
			System.err.println("ERROR: No data to calculate....");
			return 0.0D;
		}
		ROCPNPoint pnpoint = (ROCPNPoint) elementAt(0);
		double d = pnpoint.getPos() / totPos;
		double d1 = pnpoint.getNeg() / totNeg;
		double d2 = 0.5D * d * d1;
		for (int i = 1; i < size(); i++) {
			ROCPNPoint pnpoint2 = (ROCPNPoint) elementAt(i);
			double d3 = pnpoint2.getPos() / totPos;
			double d4 = pnpoint2.getNeg() / totNeg;
			double d5 = (d3 - d) * d4;
			double d6 = 0.5D * (d3 - d) * (d4 - d1);
			d2 += d5 - d6;
			ROCPNPoint pnpoint1 = pnpoint2;
			d = d3;
			d1 = d4;
		}

		d2 = 1.0D - d2;
		System.out.println((new StringBuilder())
				.append("Area Under the Curve for ROC is ").append(d2)
				.toString());
		return d2;
	}

	public void writePRFile(String s) {
		System.out.println((new StringBuilder()).append("--- Writing PR file ")
				.append(s).append(" ---").toString());
		if (size() == 0) {
			System.err.println("ERROR: No data to write....");
			return;
		}
		try {
			PrintWriter printwriter = new PrintWriter(new FileWriter(
					new File(s)));
			for (int i = 0; i < size(); i++) {
				ROCPNPoint pnpoint = (ROCPNPoint) elementAt(i);
				double d = pnpoint.getPos() / totPos;
				double d1 = pnpoint.getPos()
						/ (pnpoint.getPos() + pnpoint.getNeg());
				printwriter.println((new StringBuilder()).append(d1)
						.append("\t").append(d).toString());
			}

			printwriter.close();
		} catch (IOException ioexception) {
			System.out.println((new StringBuilder())
					.append("ERROR: IO Exception in file ").append(s)
					.append(" - exiting...").toString());
			System.exit(-1);
		}
	}

	/**
	 * recall - precision
	 * @return
	 */
	public double[][] getPR() {
		double[][] results = new double[size()][2];
		for (int i = 0; i < size(); i++) {
			ROCPNPoint pnpoint = (ROCPNPoint) elementAt(i);
			double d = pnpoint.getPos() / totPos;
			double d1 = pnpoint.getPos()
					/ (pnpoint.getPos() + pnpoint.getNeg());
			results[i][0] = d1;
			results[i][1] = d;
		}
		return results;
	}

	public double[][] getSPR() {
		ArrayList<double[]> prs = new ArrayList<>();
		int i = 0;
		ROCPNPoint pnpoint = null;
		ROCPNPoint pnpoint1 = (ROCPNPoint) elementAt(i);
		for (double d = 1.0D; d <= 100D; d++) {
			double d1 = pnpoint1.getPos() / totPos;
			double d2 = -1D;
			if (d / 100D <= d1) {
				if (pnpoint == null) {
					d2 = pnpoint1.getPos()
							/ (pnpoint1.getPos() + pnpoint1.getNeg());
				} else {
					double d3 = pnpoint1.getPos() - pnpoint.getPos();
					double d5 = pnpoint1.getNeg() - pnpoint.getNeg();
					double d7 = d5 / d3;
					double d9 = (d / 100D) * totPos;
					double d11 = pnpoint.getNeg() + (d9 - pnpoint.getPos())
							* d7;
					d2 = d9 / (d9 + d11);
				}
				prs.add(new double[] { d2, d / 100D });
				// printwriter.println((new StringBuilder()).append(d / 100D)
				// .append("\t").append(d2).toString());
				continue;
			}
			do {
				pnpoint = pnpoint1;
				pnpoint1 = (ROCPNPoint) elementAt(++i);
				d1 = pnpoint1.getPos() / totPos;
			} while (d / 100D > d1);
			double d4 = pnpoint1.getPos() - pnpoint.getPos();
			double d6 = pnpoint1.getNeg() - pnpoint.getNeg();
			double d8 = d6 / d4;
			double d10 = (d / 100D) * totPos;
			double d12 = pnpoint.getNeg() + (d10 - pnpoint.getPos()) * d8;
			d2 = d10 / (d10 + d12);
			prs.add(new double[] { d2, d / 100D });
			// printwriter.println((new StringBuilder()).append(d / 100D)
			// .append("\t").append(d2).toString());
		}
		return prs.toArray(new double[prs.size()][]);
	}

	public void writeStandardPRFile(String s) {
		System.out.println((new StringBuilder())
				.append("--- Writing standardized PR file ").append(s)
				.append(" ---").toString());
		if (size() == 0) {
			System.err.println("ERROR: No data to write....");
			return;
		}
		try {
			PrintWriter printwriter = new PrintWriter(new FileWriter(
					new File(s)));
			int i = 0;
			ROCPNPoint pnpoint = null;
			ROCPNPoint pnpoint1 = (ROCPNPoint) elementAt(i);
			for (double d = 1.0D; d <= 100D; d++) {
				double d1 = pnpoint1.getPos() / totPos;
				double d2 = -1D;
				if (d / 100D <= d1) {
					if (pnpoint == null) {
						d2 = pnpoint1.getPos()
								/ (pnpoint1.getPos() + pnpoint1.getNeg());
					} else {
						double d3 = pnpoint1.getPos() - pnpoint.getPos();
						double d5 = pnpoint1.getNeg() - pnpoint.getNeg();
						double d7 = d5 / d3;
						double d9 = (d / 100D) * totPos;
						double d11 = pnpoint.getNeg() + (d9 - pnpoint.getPos())
								* d7;
						d2 = d9 / (d9 + d11);
					}
					printwriter.println((new StringBuilder()).append(d / 100D)
							.append("\t").append(d2).toString());
					continue;
				}
				do {
					pnpoint = pnpoint1;
					pnpoint1 = (ROCPNPoint) elementAt(++i);
					d1 = pnpoint1.getPos() / totPos;
				} while (d / 100D > d1);
				double d4 = pnpoint1.getPos() - pnpoint.getPos();
				double d6 = pnpoint1.getNeg() - pnpoint.getNeg();
				double d8 = d6 / d4;
				double d10 = (d / 100D) * totPos;
				double d12 = pnpoint.getNeg() + (d10 - pnpoint.getPos()) * d8;
				d2 = d10 / (d10 + d12);
				printwriter.println((new StringBuilder()).append(d / 100D)
						.append("\t").append(d2).toString());
			}

			printwriter.close();
		} catch (IOException ioexception) {
			System.out.println((new StringBuilder())
					.append("ERROR: IO Exception in file ").append(s)
					.append(" - exiting...").toString());
			System.exit(-1);
		}
	}

	public void writeROCFile(String s) {
		System.out.println((new StringBuilder())
				.append("--- Writing ROC file ").append(s).append(" ---")
				.toString());
		if (size() == 0) {
			System.err.println("ERROR: No data to write....");
			return;
		}
		try {
			PrintWriter printwriter = new PrintWriter(new FileWriter(
					new File(s)));
			printwriter.println("0\t0");
			for (int i = 0; i < size(); i++) {
				ROCPNPoint pnpoint = (ROCPNPoint) elementAt(i);
				double d = pnpoint.getPos() / totPos;
				double d1 = pnpoint.getNeg() / totNeg;
				printwriter.println((new StringBuilder()).append(d1)
						.append("\t").append(d).toString());
			}

			printwriter.close();
		} catch (IOException ioexception) {
			System.out.println((new StringBuilder())
					.append("ERROR: IO Exception in file ").append(s)
					.append(" - exiting...").toString());
			System.exit(-1);
		}
	}

	public double[][] getROC() {
		double[][] result = new double[size()][2];
		for (int i = 0; i < size(); i++) {
			ROCPNPoint pnpoint = (ROCPNPoint) elementAt(i);
			double d = pnpoint.getPos() / totPos;
			double d1 = pnpoint.getNeg() / totNeg;
			result[i][0] = d1;
			result[i][1] = d;
		}
		return result;
	}

	public String toString() {
		String s = "";
		s = (new StringBuilder()).append(s).append("TotPos: ").append(totPos)
				.append(", TotNeg: ").append(totNeg).append("\n").toString();
		for (int i = 0; i < size(); i++)
			s = (new StringBuilder()).append(s).append(elementAt(i))
					.append("\n").toString();

		return s;
	}

	private double totPos;
	private double totNeg;

	public static void main(String[] args) {
		double[][] m = new double[][] { { 0.16666666666666666, 1.0 },
				{ 0.3333333333333333, 1.0 },
				{ 0.3333333333333333, 0.6666666666666666 }, { 0.5, 0.75 },
				{ 0.6666666666666666, 0.8 },
				{ 0.8333333333333334, 0.8333333333333334 },
				{ 0.8333333333333334, 0.7142857142857143 },
				{ 0.8333333333333334, 0.625 }, { 1.0, 0.6666666666666666 },
				{ 1.0, 0.6 } };

		ROCConfusion confusion = new ROCConfusion(6, 4);

		for (int i = 0; i < m.length; ++i) {
			confusion.addPRPoint(m[i][0], m[i][1]);
		}
		
		confusion.sort();
		confusion.interpolate();
		double [][] m2 = confusion.getROC();
		for (double[] row : m2) {
			System.out.println(Arrays.toString(row));
		}
	}
}