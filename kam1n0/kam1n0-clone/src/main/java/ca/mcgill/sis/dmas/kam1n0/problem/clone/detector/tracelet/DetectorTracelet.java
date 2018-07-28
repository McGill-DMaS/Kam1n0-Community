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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.tracelet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kenai.jnr.x86asm.Asm;

import ca.mcgill.sis.dmas.env.LocalJobProgress;
import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Binary;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.impl.storage.ram.ObjectFactoryRAM;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneEntry;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.utils.Tracelet;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.utils.TraceletGenerator;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class DetectorTracelet extends FunctionCloneDetector {

	private static Logger logger = LoggerFactory.getLogger(DetectorTracelet.class);

	public static DetectorTracelet getDetectorTraceletRam() {
		return new DetectorTracelet(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "Tracelet", "tracelet"));
	}

	public DetectorTracelet(AsmObjectFactory factory, int K, double Beta) {
		super(factory);
		this.k = K;
		this.beta = Beta;
	}

	public DetectorTracelet(AsmObjectFactory factory) {
		this(factory, 1, 0.9);
	}

	TraceletGenerator generator = new TraceletGenerator();

	HashMap<Long, ArrayList<PreSplittedBlock>> data = new HashMap<>();
	int k = 4;
	double beta = 0.7;

	@Override
	protected List<FunctionCloneEntry> detectClonesForFuncToBeImpleByChildren(long rid, Function function,
			double threadshold, int topK, boolean avoidSameBinary) throws Exception {

		ArrayList<PreSplittedBlock> pblk = data.get(function.functionId);
		if (pblk == null) {
			final ArrayList<PreSplittedBlock> pblkt = new ArrayList<>();
			function.forEach(blk -> pblkt.add(new PreSplittedBlock(blk)));
			data.put(function.functionId, pblk);
			pblk = pblkt;
		}

		final ArrayList<PreSplittedBlock> pblkc = pblk;
		return data.entrySet()
				//
				.stream()
				//
				.filter(entry -> !entry.getKey().equals(function.functionId))
				//
				.map(entry -> {
					Function srcFunc = this.factory.obj_functions.querySingle(rid, entry.getKey());
					if (avoidSameBinary && srcFunc.binaryId == function.binaryId)
						return null;
					return new FunctionCloneEntry(srcFunc, this.compareTo(pblkc, entry.getValue()));
				}) //
				.filter(fce -> fce != null).collect(Collectors.toList());
	}

	@Override
	protected void indexFuncsToBeImplByChildren(long rid, List<Binary> binaries, LocalJobProgress progress)
			throws Exception {
		logger.info("Pre-splitting instructions...");
		binaries.stream().flatMap(bin -> bin.functions.stream()).forEach(func -> {
			ArrayList<PreSplittedBlock> pblks = new ArrayList<>();
			func.forEach(blk -> pblks.add(new PreSplittedBlock(blk)));
			data.put(func.functionId, pblks);
		});
	}

	@Override
	public void init() throws Exception {

	}

	@Override
	public void close() throws Exception {

	}

	public double compareTo(List<PreSplittedBlock> funcFrom, List<PreSplittedBlock> funcTo) {
		ArrayList<Tracelet> ff = generator.generateGraphlets(funcFrom, k);
		ArrayList<Tracelet> ft = generator.generateGraphlets(funcTo, k);
		int count = 0;
		ArrayList<Double> ftf = new ArrayList<>();
		ArrayList<Double> ttt = new ArrayList<>();
		for (Tracelet f : ff)
			ftf.add(compareTo(f, f));
		for (Tracelet t : ft)
			ttt.add(compareTo(t, t));

		for (int i = 0; i < ff.size(); ++i) {
			for (int j = i + 1; j < ft.size(); ++j) {
				double S = compareTo(ff.get(i), ft.get(j));
				double fI = ftf.get(i);
				double tI = ttt.get(j);
				double fs = (S * 2) / (fI + tI);
				if (fs >= beta)
					count++;
			}
		}
		return count * 1.0 / (ff.size());
	}

	public static boolean debug = false;

	public static double compareTo(Tracelet tr1, Tracelet tr2) {
		int dim1 = tr1.size();
		int dim2 = tr2.size();
		double[][] M = new double[dim1][dim2];
		double[][] B = new double[dim1][dim2];

		for (int i = 0; i < dim1; ++i) {
			double g = cmpInstruction(tr1.get(i), tr2.get(0));
			M[i][0] = -2;
			B[i][0] = g;
		}

		for (int j = 0; j < dim2; ++j) {
			double g = cmpInstruction(tr1.get(0), tr2.get(j));
			M[0][j] = -2;
			B[0][j] = g;
		}

		for (int i = 1; i < dim1; ++i)
			for (int j = 1; j < dim2; ++j) {
				double g = cmpInstruction(tr1.get(i), tr2.get(j)) + B[i - 1][j - 1];
				M[i][j] = g;
				B[i][j] = max(g, B[i][j - 1], B[i - 1][j]);
				if (B[i][j] == g) {
					M[i][j] = 0;
				} else if (B[i][j - 1] == g) {
					M[i][j] = 1;
				} else {
					M[i][j] = -1;
				}
			}

		if (debug) {
			StringBuilder sBuilder = new StringBuilder();
			StringBuilder mBuilder = new StringBuilder();
			StringBuilder bBuilder = new StringBuilder();
			for (int i = 0; i < dim1; ++i) {
				for (int j = 0; j < dim2; ++j) {
					mBuilder.append(M[i][j]).append(" ");
					bBuilder.append(B[i][j]).append(" ");
					if (M[i][j] == B[i][j])
						sBuilder.append(1).append(" ");
					else
						sBuilder.append(0).append(" ");
				}
				sBuilder.append(StringResources.STR_LINEBREAK);
				mBuilder.append(StringResources.STR_LINEBREAK);
				bBuilder.append(StringResources.STR_LINEBREAK);
			}
			System.out.println(sBuilder.toString());
			System.out.println();
			System.out.println(mBuilder.toString());
			System.out.println();
			System.out.println(bBuilder.toString());

			ArrayList<Integer> dels = new ArrayList<>();
			ArrayList<Integer> ins = new ArrayList<>();
			ArrayList<Integer> keps = new ArrayList<>();
			int i = dim1 - 1, j = dim2 - 1;
			while (i >= 0 && j >= 0) {
				double direc = M[i][j];
				if (direc == 0) {
					keps.add(i);
					i--;
					j--;
				} else if (direc == 1) {
					ins.add(j);
					j--;
				} else if (direc == -1) {
					dels.add(i);
					i--;
				}
				if (direc == -2)
					break;
			}
			while (i >= 0) {
				dels.add(i--);
			}
			while (j >= 0) {
				ins.add(j--);
			}

			System.out.println(keps);
			System.out.println(ins);
			System.out.println(dels);
		}

		return B[dim1 - 1][dim2 - 1];
	}

	private static double max(double... dbs) {
		double r = -1;
		for (double d : dbs) {
			r = r > d ? r : d;
		}
		return r;
	}

	/**
	 * 
	 * @param cmd1
	 * @param cmd2
	 * @return
	 */
	public static double cmpInstruction(String cmd1, String cmd2) {
		if (cmd1.length() == 0 || cmd2.length() == 0)
			return 0;

		String[] cmd1parts = cmd1.split("\\s+");
		String[] cmd2parts = cmd2.split("\\s+");

		if (cmd1parts.length < 2 || cmd2parts.length < 2)
			return 0;

		if (!cmd1parts[1].equals(cmd2parts[1]))
			return -1;

		int tg = 2;

		if (cmd1parts.length < 3 || cmd2parts.length < 3)
			return tg;

		for (int i = 2; i < Math.min(cmd1parts.length, cmd2parts.length); ++i) {
			if (cmd1parts[i].startsWith(";") || cmd2parts[i].startsWith(";"))
				break;
			String[] cmd1paramiElements = cmd1parts[i].split("\\+");
			String[] cmd2paramiElements = cmd2parts[i].split("\\+");
			if (cmd1paramiElements.length == cmd2paramiElements.length)
				tg++;
		}

		return tg;
	}

	/**
	 * 
	 * @param cmd1
	 * @param cmd2
	 * @return
	 */
	public static double cmpInstruction(EntryPair<String, ArrayList<Integer>> cmd1,
			EntryPair<String, ArrayList<Integer>> cmd2) {

		if (!cmd1.key.equals(cmd2.key))
			return -1;

		int tg = 2;

		for (int i = 2; i < Math.min(cmd1.value.size(), cmd2.value.size()); ++i) {
			if (cmd1.value.get(i).equals(cmd2.value.get(i)))
				tg++;
		}

		return tg;
	}

	@Override
	public String params() {
		return StringResources.JOINER_TOKEN_CSV.join("K", k, "Beta", beta);
	}

	public static void main(String[] args) throws Exception {
		System.out.print(cmpInstruction("4096 push\t[ebp+1], 1 ", "4100 push\t[ebp+arg_0] ; sdfwerwerc"));

		System.out.println();

		DetectorTracelet detector = DetectorTracelet.getDetectorTraceletRam();
		BinarySurrogate bs = BinarySurrogate
				.load("E:\\kam1no\\kam1n0-debugSymbol\\libpng\\asms\\libpng15.dll.239a283e49f5431f.json");
		// System.out.println(detector.compareTo(bs.functions.get(0),
		// bs.functions.get(0)));
	}

	public static class PreSplittedBlock {
		public ArrayList<EntryPair<String, ArrayList<Integer>>> ins = new ArrayList<>();
		public Block orinBlock;

		public PreSplittedBlock(Block blk) {
			orinBlock = blk;
			for (List<String> line : blk) {
				if (line.size() < 2)
					continue;
				EntryPair<String, ArrayList<Integer>> entry = new EntryPair<String, ArrayList<Integer>>(line.get(1),
						new ArrayList<>());
				ins.add(entry);
				for (int i = 2; i < line.size(); ++i) {
					if (line.get(i).startsWith(";"))
						break;
					String[] subparts = line.get(i).split("\\+");
					entry.value.add(subparts.length);
				}
			}
		}
	}

}
