package kam1n0;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class Model {

	public Binary bin;
	public List<Func> functions = new ArrayList<>();
	public List<FuncSrc> functions_src = new ArrayList<>();
	public List<Block> blocks = new ArrayList<>();
	public List<Comment> comments = new ArrayList<>();

	public static class Binary {
		public Long base = 0l;
		public List<String> import_modules = new ArrayList<>();
		public Map<Long, List<String>> import_functions = new HashMap<>();
		public Map<Long, String> export_functions = new HashMap<>();
		public Map<Long, String> seg = new HashMap<>();
		public String disassembled_at = "";
		public int functions_count = 0;
		public String architecture = "";
		public String disassembler = "ghidra";
		public String endian = "";
		public String bits = "";
		public Map<Long, String> strings = new HashMap<>();
		public Map<Long, String> data = new HashMap<>();
		public String compiler = "";
		public String name;
		public String sha256;
		public List<Long> entry_points = new ArrayList<>();

	}

	public static class Func {
		public long addr_start;
		public List<Long> calls = new ArrayList<>();
		public int bbs_len = 0;
		public long addr_end;
		public String name = "";
	}

	public static class FuncSrc {
		public long addr_start;
		public String src = "";
	}

	public static class Block {
		public long addr_start;
		public String name = "";
		public List<Long> calls = new ArrayList<>();
		public long addr_end;
		public long addr_f;
		public List<Ins> ins = new ArrayList<>();
	}

	public static class Ins {
		public long ea;
		public String mne = "";
		public List<String> oprs = new ArrayList<>();
		public List<Integer> oprs_tp = new ArrayList<>();
		public List<Long> dr = new ArrayList<>();
		public List<Long> cr = new ArrayList<>();
	}

	public static class Comment {
		public int category = 3;
		public String content = "";
		public String author = "ghidra";
		public String created_at = "";
		public long address;
		public long func;
	}


}