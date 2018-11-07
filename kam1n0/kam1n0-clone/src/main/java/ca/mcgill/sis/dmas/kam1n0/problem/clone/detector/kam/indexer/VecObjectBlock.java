package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.indexer;

import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmFragmentNormalized;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecFullKeyCalculator;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.index.VecObject;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureConstructor;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashUtils;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.SparseVector;

public class VecObjectBlock implements VecObject<VecInfoBlock, VecInfoSharedBlock> {

	private static final long serialVersionUID = 6026996636667058123L;
	public Block block;
	public transient AsmFragmentNormalized tkns;
	public transient FeatureConstructor featureGenerator;

	public VecObjectBlock(Block block, FeatureConstructor featureGenerator) {
		this.block = new Block(block);
		this.block.architecture = null;
		this.block.bytes = null;
		this.block.codes = null;
		this.block.binaryName = "";
		this.block.dat = null;
//		this.block.functionName = "";
		this.tkns = featureGenerator.tokenizeAsmFragment(block);
		this.featureGenerator = featureGenerator;
	}

	@Override
	public long getUniqueHash() {
		return HashUtils.hashTkns(tkns);
	}

	@Override
	public VecFullKeyCalculator getFullKeyCalculator(HashSchema schema) {
		return () -> {
			SparseVector vec = this.featureGenerator.scoreNormalizedFragment(tkns);
			if (vec.noEntry())
				return new byte[] {};
			return schema.hash(vec);
		};
	}

	@Override
	public VecInfoSharedBlock getSharedInfo() {
		return new VecInfoSharedBlock();
	}

	@Override
	public VecInfoBlock getSelfInfo() {
		return new VecInfoBlock(this.block);
	}

	@Override
	public byte[] hash(HashSchema schema) {
		SparseVector vec = this.featureGenerator.scoreNormalizedFragment(tkns);
		if (vec.noEntry())
			return new byte[] {};
		return schema.hash(vec);
	}
	
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return Long.toString(block.blockId) + block.blockName;
	}

}
