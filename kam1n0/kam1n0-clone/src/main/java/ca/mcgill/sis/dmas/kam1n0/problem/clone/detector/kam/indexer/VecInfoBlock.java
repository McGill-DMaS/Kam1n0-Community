package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.indexer;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecInfo;

public class VecInfoBlock extends VecInfo {

	private static final long serialVersionUID = -3479056402501158941L;

	public VecInfoBlock() {
	}

	public VecInfoBlock(Block blk) {
		this.functionId = blk.functionId;
		this.blockId = blk.blockId;
		this.blockLength = (int) blk.codesSize;
		this.calls = blk.callingBlocks.toArray(new Long[blk.callingBlocks.size()]);
		this.peerSize = blk.peerSize;
	}

	public Long functionId;
	public Long blockId;
	public Integer blockLength;
	public Long[] calls;
	public int peerSize;	// TODO: can be total function block count or instruction count. clear that up.
	public int funcLength;
	
	

}