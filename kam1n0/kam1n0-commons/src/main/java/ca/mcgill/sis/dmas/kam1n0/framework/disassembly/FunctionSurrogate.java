package ca.mcgill.sis.dmas.kam1n0.framework.disassembly;

import java.util.ArrayList;
import java.util.Iterator;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.collect.Iterables;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Comment.CommentType;

@JsonIgnoreProperties(ignoreUnknown = true)
public class FunctionSurrogate implements Iterable<BlockSurrogate> {

	public String name;
	public long id;
	public long srcid = -1;
	public String srcName = StringResources.STR_EMPTY;

	public String concateName() {
		return this.name + "-" + this.srcName;
	}

	public long sea;
	public long see;
	public ArrayList<Long> call = new ArrayList<Long>();
	public ArrayList<BlockSurrogate> blocks = new ArrayList<BlockSurrogate>();
	public ArrayList<String> api = new ArrayList<>();
	public ArrayList<FunctionSurrogate.CommentSurrogate> comments = new ArrayList<>();

	@JsonIgnore
	@Override
	public Iterator<BlockSurrogate> iterator() {
		return blocks.iterator();
	}

	@Override
	public int hashCode() {
		return Long.hashCode(id);
	}

	public static class CommentSurrogate {
		public String offset;
		public CommentType type;
		public String comment;
	}

	public String toSrcCode(AsmLineNormalizer normalizer) {
		return StringResources.JOINER_LINE.join(Iterables.transform(
				normalizer.tokenizeAsmLines(Iterables.concat(blocks)), AsmLineNormalizer::formatCodeLine));
	}

	public String toSrcCode() {
		return StringResources.JOINER_LINE
				.join(Iterables.transform(Iterables.concat(blocks), AsmLineNormalizer::formatCodeLine));
	}

	public int getNumberOfBlocks() {
		return blocks.size();
	}
}