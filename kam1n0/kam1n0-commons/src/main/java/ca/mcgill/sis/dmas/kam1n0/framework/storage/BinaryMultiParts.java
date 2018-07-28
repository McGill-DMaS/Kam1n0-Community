package ca.mcgill.sis.dmas.kam1n0.framework.storage;

import java.util.Iterator;

public class BinaryMultiParts implements Iterable<Binary> {

	private Iterable<Binary> parts;
	private int size;

	public BinaryMultiParts(Iterable<Binary> parts, int size) {
		this.parts = parts;
		this.size = size;
	}

	public int getSize() {
		return this.size;
	}

	@Override
	public Iterator<Binary> iterator() {
		return this.parts.iterator();
	}
}
