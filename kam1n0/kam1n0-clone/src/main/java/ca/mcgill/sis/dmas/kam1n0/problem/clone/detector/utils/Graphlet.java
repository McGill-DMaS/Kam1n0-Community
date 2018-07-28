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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.utils;

import gnu.trove.map.hash.TLongObjectHashMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;

import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public class Graphlet {

	public Graphlet(List<Block> blocks, boolean extended, List<Block> allBlks) {
		blocks = canonicalOrder(blocks);
		this.signature = orderedBlockToString(blocks, extended, allBlks);
	}

	private String orderedBlockToString(List<Block> blocks, boolean extended, List<Block> allBlks) {
		if (!extended) {
			byte[] bytes = new byte[blocks.size()];
			for (int i = 0; i < blocks.size(); ++i) {
				bytes[i] = 0;
				for (int j = 0; j < blocks.size(); ++j) {
					long bid = blocks.get(j).blockId;
					bytes[i] = (byte) (bytes[i] << 1);
					for (Long cid : blocks.get(i).callingBlocks) {
						if (cid.equals(bid)) {
							bytes[i] |= 1;
							break;
						}
					}
				}
			}
			return bytesToHex(bytes);
		} else {
			byte[] bytes = new byte[blocks.size() + 1];
			for (int i = 0; i < blocks.size(); ++i) {
				bytes[i] = 0;
				for (int j = 0; j < blocks.size(); ++j) {
					long bid = blocks.get(j).blockId;
					bytes[i] = (byte) (bytes[i] << 1);
					for (Long cid : blocks.get(i).callingBlocks) {
						if (cid.equals(bid)) {
							bytes[i] |= 1;
							break;
						}
					}
				}
				// check in degree:
				for (Block tb : allBlks) {
					if (tb.callingBlocks.contains(blocks.get(i).blockId)) {
						boolean find = false;
						for (Block gb : blocks) {
							if (gb.blockId == tb.blockId) {
								find = true;
								break;
							}
						}
						if (!find) {
							bytes[i] = (byte) (bytes[i] << 1);
							bytes[i] |= 1;
							break;
						}
					}
				}
				// check outdegree:
				boolean find = false;
				for (Long cid : blocks.get(i).callingBlocks) {
					for (Block tb : allBlks) {
						if (tb.blockId == cid) {
							for (Block gb : blocks) {
								if (gb.blockId == tb.blockId) {
									// find an outlink
									find = true;
									break;
								}
							}
							if (!find) {
								bytes[bytes.length - 1] = (byte) (bytes[bytes.length - 1] | (1 << (blocks.size() - i)));
								break;
							}
						}
					}
					if (!find)
						break;
				}
			}

			return bytesToHex(bytes);
		}
	}

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	private static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	private List<Block> canonicalOrder(List<Block> blks) {
		ArrayList<ArrayList<Block>> partition = new ArrayList<>();
		partition.add(new ArrayList<>(blks));
		refine(partition);
		return searchMax(partition, blks.size());
	}

	private void refine(ArrayList<ArrayList<Block>> partition) {
		while (searchShattering(partition))
			;
	}

	private boolean searchShattering(ArrayList<ArrayList<Block>> partition) {
		for (int i = 0; i < partition.size(); ++i)
			for (int j = 0; j < partition.size(); ++j)
				if (shatters(partition.get(i), partition.get(j)))
					return shattering(partition, i, j);
		return false;
	}

	private boolean shatters(ArrayList<Block> from, ArrayList<Block> to) {
		int deg = -1;
		for (int i = 0; i < from.size(); ++i) {
			int sdeg = deg(from.get(i), to);
			if (deg == -1)
				deg = sdeg;
			if (deg != sdeg)
				return true;
		}
		return false;
	}

	private int deg(Block bis, ArrayList<Block> to) {
		int sdeg = 0;
		for (Long callee : bis.callingBlocks) {
			for (Block tblock : to) {
				if (callee.equals(tblock.blockId)) {
					sdeg++;
					break;
				}
			}
		}
		return sdeg;
	}

	private boolean shattering(ArrayList<ArrayList<Block>> partition, int from, int to) {
		TLongObjectHashMap<ArrayList<Block>> map = new TLongObjectHashMap<>();
		for (Block fblock : partition.get(from)) {
			int deg = deg(fblock, partition.get(to));
			ArrayList<Block> list = map.get(deg);
			if (list == null) {
				list = new ArrayList<>();
				map.put(deg, list);
			}
			list.add(fblock);
		}
		long[] keys = map.keys().clone();
		Arrays.sort(keys);
		partition.remove(from);
		for (long key : keys) {
			partition.add(from, map.get(key));
		}
		return true;
	}

	private ArrayList<Block> searchMax(ArrayList<ArrayList<Block>> partition, int total) {
		search(partition, 0, total, new Stack<>());
		return new ArrayList<>(maxPerm);
	}

	private String currentMax = null;
	private List<Block> maxPerm = null;

	@SuppressWarnings("unchecked")
	private void search(ArrayList<ArrayList<Block>> partition, int index, int total, Stack<Block> output) {
		if (output.size() == total) {
			String sig = orderedBlockToString(output, false, null);
			if (currentMax == null || sig.compareTo(currentMax) > 0) {
				currentMax = sig;
				maxPerm = (List<Block>) output.clone();
			}
			return;
		}
		for (List<Block> perm : Collections2.permutations(partition.get(index))) {
			for (Block blk : perm)
				output.push(blk);
			search(partition, index + 1, total, output);
			for (int i = 0; i < perm.size(); ++i)
				output.pop();
		}
	}

	public String signature;

	public static void main(String[] args) {
		Block b1 = new Block();
		b1.binaryId = 1;
		b1.callingBlocks = new ArrayList<>();
		b1.callingBlocks.add(4l);
		b1.callingBlocks.add(2l);
		Block b2 = new Block();
		b2.binaryId = 2;
		b2.callingBlocks = new ArrayList<>();
		b2.callingBlocks.add(1l);
		b2.callingBlocks.add(3l);
		Block b3 = new Block();
		b3.binaryId = 3;
		b3.callingBlocks = new ArrayList<>();
		b3.callingBlocks.add(2l);
		b3.callingBlocks.add(4l);
		Block b4 = new Block();
		b4.binaryId = 4;
		b4.callingBlocks = new ArrayList<>();
		b4.callingBlocks.add(3l);
		b4.callingBlocks.add(1l);
		Block b5 = new Block();
		b5.binaryId = 5;
		b5.callingBlocks = new ArrayList<>();
		b5.callingBlocks.add(1l);
		b5.callingBlocks.add(2l);
		b5.callingBlocks.add(3l);
		b5.callingBlocks.add(4l);

		Stack<Block> bls = new Stack<>();
		bls.add(b1);
		bls.add(b2);
		bls.add(b3);
		bls.add(b4);
		bls.add(b5);
		Graphlet gl = new Graphlet(bls, false, null);
		System.out.println(gl.signature);

		Function func = new Function();
		func.blocks = new ArrayList<>();
		func.blocks.addAll(bls);
		GraphletGenerator gg = new GraphletGenerator(3, true);
		ArrayList<Graphlet> gs = gg.generateGraphlets(func, 3, true);
		gs.forEach(g -> System.out.println(g.signature));

		Collections2.permutations(ImmutableList.of("1", "2", "3")).forEach(p -> System.out.println(p));
	}
}
