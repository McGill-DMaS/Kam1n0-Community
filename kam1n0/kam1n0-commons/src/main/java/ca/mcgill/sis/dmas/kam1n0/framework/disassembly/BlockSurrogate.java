package ca.mcgill.sis.dmas.kam1n0.framework.disassembly;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BlockSurrogate implements Iterable<List<String>> {

	public long id;
	public long srcid = -1;
	public String bytes;

	// start end
	public long sea;
	public long eea;
	public String name;

	// cfg
	public ArrayList<Long> call = new ArrayList<Long>();
	public ArrayList<List<String>> src = new ArrayList<>();
	public ArrayList<List<Integer>> oprTypes = new ArrayList<>();
	public HashMap<Long, String> dat = new HashMap<>();

	@JsonIgnore
	@Override
	public Iterator<List<String>> iterator() {
		return src.iterator();
	}

	public List<List<String>> asmLines() {
		return src;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(id);
	}
}