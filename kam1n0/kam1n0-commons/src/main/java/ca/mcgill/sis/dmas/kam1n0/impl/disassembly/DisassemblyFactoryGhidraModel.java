package ca.mcgill.sis.dmas.kam1n0.impl.disassembly;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.Endianness;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.InstructionSize;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BinarySurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.BlockSurrogate;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.FunctionSurrogate;
import scala.Tuple2;

public class DisassemblyFactoryGhidraModel {

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
		public List<Long> calls;
		public String bin_id = "";
		public int bbs_len = 0;
		public long addr_end;
		public String description = "";
		public String name = "";
		public List<String> api = new ArrayList<>();
	}

	public static class FuncSrc {
		public String _id = "";
		public String src = "";
	}

	public static class Block {
		public long addr_start;
		public String bin_id = "";
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
		public List<String> oprs_tp = new ArrayList<>();
		public List<Long> dr = new ArrayList<>();
		public List<Long> cr = new ArrayList<>();

		public List<String> toTokens() {
			ArrayList<String> tokens = new ArrayList<>();
			tokens.add(Long.toHexString(ea));
			tokens.add(mne);
			tokens.addAll(oprs);
			return tokens;
		}
	}

	public static class Comment {

		public int category = 3;
		public String content = "";
		public String author = "ghidra";
		public String created_at = "";
		public long address;
		public long func;
	}

	public BinarySurrogate toBinarySurrogate() {
		BinarySurrogate bin = new BinarySurrogate();
		bin.architecture.type = ArchitectureType.valueOf(this.bin.architecture);
		bin.architecture.size = InstructionSize.valueOf(this.bin.bits);
		bin.architecture.endian = Endianness.valueOf(this.bin.endian);
		bin.hash = this.bin.sha256.hashCode();
		bin.md5 = this.bin.sha256;
		bin.name = this.bin.name;

		Map<Long, ArrayList<BlockSurrogate>> funcBlockMap = new HashMap<>();
		this.blocks.stream().map(b -> {
			BlockSurrogate bs = new BlockSurrogate();
			bs.call = new ArrayList<>(b.calls);
			bs.eea = b.addr_end;
			bs.sea = b.addr_start;
			bs.id = b.addr_start;
			bs.name = b.name;
			bs.src = b.ins.stream().map(ins -> ins.toTokens()).collect(Collectors.toCollection(ArrayList::new));
			return new Tuple2<>(bs, b.addr_f);
		}).forEach(b -> {
			funcBlockMap.compute(b._2, (k, v) -> v == null ? new ArrayList<>() : v).add(b._1);
		});

		bin.functions = this.functions.stream().map(f -> {
			FunctionSurrogate fs = new FunctionSurrogate();
			fs.name = f.name;
			fs.id = f.addr_start;
			fs.api = new ArrayList<>(f.api);
			fs.call = new ArrayList<>(f.calls);
			fs.sea = f.addr_start;
			fs.see = f.addr_end;
			fs.blocks = funcBlockMap.get(f.addr_start);
			return fs;
		}).collect(Collectors.toCollection(ArrayList::new));
		return bin;
	}

	private static ObjectMapper mapper = new ObjectMapper();

	public static BinarySurrogate load(File file) throws Exception {
		try {
			return mapper.readValue(file, DisassemblyFactoryGhidraModel.class).toBinarySurrogate();
		} catch (Exception e) {
			byte[] bytes = Files.readAllBytes(file.toPath());
			Charset charset = Charset.forName("UTF-8");
			String json = charset.decode(ByteBuffer.wrap(bytes)).toString();
			return mapper.readValue(json, BinarySurrogate.class);
		}
	}

}
