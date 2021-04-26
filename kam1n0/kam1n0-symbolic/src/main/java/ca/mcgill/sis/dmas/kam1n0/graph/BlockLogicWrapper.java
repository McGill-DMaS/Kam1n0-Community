package ca.mcgill.sis.dmas.kam1n0.graph;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmLineNormalizer;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Block;
import ca.mcgill.sis.dmas.kam1n0.vex.VEXIRBB;
import org.sparkproject.guava.collect.ImmutableMap;

public class BlockLogicWrapper extends Block {
	private static final long serialVersionUID = 3835277277624159207L;
	// transient OBJS ignored in web data transmission
	private transient List<List<String>> vex;

	public List<List<String>> getVex() {
		return vex;
	}

	private transient LogicGraph logic;

	public BlockLogicWrapper(Block blk, List<List<String>> v, LogicGraph lg) {
		super(blk);
		vex = v;
		logic = lg;
	}

	public BlockLogicWrapper(Block blk) {
		super(blk);
		VEXIRBB bb = VEXIRBB.translateBlk(this);
		vex = bb.toVexStrs(true);
		logic = bb.translate().simplify();
	}

	public LogicGraph getLogic() {
		return logic;
	}

	public Block getBlock() {
		return this;
	}

	@Override
	public Map<String, Object> fillWebAttr() {
		return ImmutableMap.of("vex", vex.stream().map(AsmLineNormalizer::formatCodeLine).collect(Collectors.toList()),
				"logic", logic.visualize(Long.toString(this.blockId), this.blockName));
	}

}
