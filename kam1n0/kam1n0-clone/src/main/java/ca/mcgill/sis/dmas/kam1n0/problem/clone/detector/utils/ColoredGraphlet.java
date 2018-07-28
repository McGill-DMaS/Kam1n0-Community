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

import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;

public class ColoredGraphlet {

	public ColoredGraphlet(List<Block> blocks, TLongObjectHashMap<String> tags) {
		this.tags = tags;
		blocks = canonicalOrder(blocks, tags);
		this.signature = orderedBlockToString(blocks, tags);
	}

	private String orderedBlockToString(List<Block> blocks, TLongObjectHashMap<String> tags) {
		byte[] bytes = new byte[blocks.size() * 2];
		for (int i = 0; i < blocks.size(); ++i) {
			bytes[i * 2] = 0;
			for (int j = 0; j < blocks.size(); ++j) {
				long bid = blocks.get(j).blockId;
				bytes[i * 2] = (byte) (bytes[i * 2] << 1);
				for (Long cid : blocks.get(i).callingBlocks) {
					if (cid.equals(bid)) {
						bytes[i * 2] |= 1;
						break;
					}
				}
			}
			bytes[i * 2 + 1] = (byte) tags.get(blocks.get(i).blockId).hashCode();
		}
		return bytesToHex(bytes);
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

	private List<Block> canonicalOrder(List<Block> blks, TLongObjectHashMap<String> map) {
		ArrayList<ArrayList<Block>> partition = new ArrayList<>();
		partition.add(new ArrayList<>(blks));
		refine(partition, map);
		return searchMax(partition, blks.size());
	}

	private void refine(ArrayList<ArrayList<Block>> partition, TLongObjectHashMap<String> map) {
		while (searchShattering(partition, map))
			;
	}

	private boolean searchShattering(ArrayList<ArrayList<Block>> partition, TLongObjectHashMap<String> map) {
		for (int i = 0; i < partition.size(); ++i)
			for (int j = 0; j < partition.size(); ++j) {
				String tag = shatters(partition.get(i), partition.get(j), map);
				if (tag != null)
					return shattering(partition, i, j, map, tag);
			}
		return false;
	}

	private String shatters(ArrayList<Block> from, ArrayList<Block> to, TLongObjectHashMap<String> map) {
		int deg = -1;
		for (String tag : map.valueCollection()) {

			for (int i = 0; i < from.size(); ++i) {
				int sdeg = deg(from.get(i), to, map, tag);
				if (deg == -1)
					deg = sdeg;
				if (deg != sdeg)
					return tag;
			}
		}
		return null;
	}

	private int deg(Block bis, ArrayList<Block> to, TLongObjectHashMap<String> map, String tag) {
		int sdeg = 0;
		String btag = map.get(bis.blockId);
		for (Long callee : bis.callingBlocks) {
			for (Block tblock : to) {
				if (callee.equals(tblock.blockId) && btag.equals(map.get(tblock.blockId))) {
					sdeg++;
					break;
				}
			}
		}
		return sdeg;
	}

	private boolean shattering(ArrayList<ArrayList<Block>> partition, int from, int to, TLongObjectHashMap<String> map2,
			String tag) {
		TLongObjectHashMap<ArrayList<Block>> map = new TLongObjectHashMap<>();
		for (Block fblock : partition.get(from)) {
			int deg = deg(fblock, partition.get(to), map2, tag);
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
			String sig = orderedBlockToString(output, tags);
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
	public TLongObjectHashMap<String> tags;

	public static void main(String[] args) {
		Block b1 = new Block();
		b1.blockId = 1;
		b1.callingBlocks = new ArrayList<>();
		b1.callingBlocks.add(4l);
		b1.callingBlocks.add(2l);
		Block b2 = new Block();
		b2.blockId = 2;
		b2.callingBlocks = new ArrayList<>();
		b2.callingBlocks.add(1l);
		b2.callingBlocks.add(3l);
		Block b3 = new Block();
		b3.blockId = 3;
		b3.callingBlocks = new ArrayList<>();
		b3.callingBlocks.add(2l);
		b3.callingBlocks.add(4l);
		Block b4 = new Block();
		b4.blockId = 4;
		b4.callingBlocks = new ArrayList<>();
		b4.callingBlocks.add(3l);
		b4.callingBlocks.add(1l);
		Block b5 = new Block();
		b5.blockId = 5;
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

		TLongObjectHashMap<String> tags = new TLongObjectHashMap<>();
		tags.put(1l, "red");
		tags.put(2l, "blue");
		tags.put(3l, "red");
		tags.put(4l, "red");
		tags.put(5l, "yellow");

		ColoredGraphlet gl = new ColoredGraphlet(bls, tags);
		System.out.println(gl.signature);

		Function func = new Function();
		func.blocks = new ArrayList<>();
		func.blocks.addAll(bls);
		ColoredGraphletGenerator gg = new ColoredGraphletGenerator(2);
		ArrayList<ColoredGraphlet> gs = gg.generateGraphletColors(func, 2, tags);
		gs.forEach(g -> System.out.println(g.signature));
	}
}
