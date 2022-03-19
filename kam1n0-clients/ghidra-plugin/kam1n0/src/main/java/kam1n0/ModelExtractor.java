package kam1n0;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;
import java.util.stream.Collectors;
import java.util.HashMap;
import java.util.HashSet;

import generic.stl.Pair;
import ghidra.framework.Platform;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

import kam1n0.Model.*;

public class ModelExtractor {

	private static final SimpleDateFormat date_formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
	private static TaskMonitor monitor = TaskMonitor.DUMMY;
	private static CodeUnitFormat format = new CodeUnitFormat(new CodeUnitFormatOptions());
	
	public static Model extract(Program program) {
		return extract(program, null);
	}

	public static Model extract(Program program, ProgramLocation loc) {
		try {
			
			
			FunctionManager functionManager = program.getFunctionManager();
			
			Function cursorFunction = null;
			if (loc != null) {
				cursorFunction = functionManager.getFunctionContaining(loc.getAddress());
				if(cursorFunction == null)
					return null;
			}
			
			BasicBlockModel basicBlockModel = new BasicBlockModel(program);

			Model model = new Model();

			Binary bin = new Binary();
			bin.sha256 = program.getExecutableSHA256();

			SymbolTable sm = program.getSymbolTable();
			HashSet<String> modules = new HashSet<>();
			for (Symbol s : sm.getExternalSymbols()) {
				String ord = null;
				String module_name = "<EXTERNAL>";
				if (s.getParentSymbol() != null)
					module_name = s.getParentSymbol().getName().toLowerCase();
				modules.add(module_name);
				long ea = s.getAddress().getOffset();
				if (s.getName().contains("Ordinal_"))
					ord = s.getName().replace("Ordinal_", "");
				List<String> info = Arrays.asList(module_name, s.getName(), ord);
				bin.import_functions.put(ea, info);

				for (Reference ref : s.getReferences()) {
					if (ref.getReferenceType() == RefType.DATA)
						bin.import_functions.put(ref.getFromAddress().getOffset(), info);
				}
			}

			AddressIterator ite = sm.getExternalEntryPointIterator();
			while (ite.hasNext()) {
				Address addr = ite.next();
				Function func = functionManager.getFunctionContaining(addr);
				bin.entry_points.add(addr.getOffset());
				if (func != null)
					bin.export_functions.put(addr.getOffset(), func.getName());
			}

			for (MemoryBlock b : program.getMemory().getBlocks()) {
				bin.seg.put(b.getStart().getOffset(), b.getName());
			}

			HashMap<Long, Data> dataMap = new HashMap<>();

			// StreamSupport.stream(program.getListing().getExternalFunctions().spliterator(),
			// false).forEach(
			// func -> bin.import_functions.put(func.getEntryPoint().getOffset(),
			// Arrays.asList(func.getName())));
			bin.name = program.getName();
			bin.base = program.getImageBase().getOffset();
			bin.disassembled_at = date_formatter.format(Calendar.getInstance().getTime());
			bin.functions_count = functionManager.getFunctionCount();
			bin.architecture = Platform.CURRENT_PLATFORM.getArchitecture().toString();
			bin.endian = program.getLanguage().isBigEndian() ? "be" : "le";
			bin.bits = "b" + program.getAddressFactory().getDefaultAddressSpace().getSize();
			for (Data dat : program.getListing().getDefinedData(true)) {
				if (dat == null || dat.getValue() == null)
					continue;
				long offset = dat.getMinAddress().getOffset();
				if (dat.hasStringValue())
					bin.strings.put(offset, dat.getValue().toString());
				else if (dat.isConstant()) {
					int size = dat.getLength();
					try {
						byte[] bytes = new byte[size];
						size = program.getMemory().getBytes(dat.getMinAddress(), bytes);
						if (size > 0)
							bin.data.put(offset, Base64.getEncoder().encodeToString(bytes));
					} catch (Exception e) {

					}
				}
				dataMap.put(offset, dat);
			}

			// if (type.contains("unicode") || type.contains("string")) {
			bin.compiler = program.getCompiler();
			model.bin = bin;

			for (Function currentFunction : functionManager.getFunctions(true)) {
				
				if (cursorFunction != null && !cursorFunction.getEntryPoint().equals(currentFunction.getEntryPoint()))
					continue;
					

				Func func = new Func();
				func.addr_start = currentFunction.getEntryPoint().getOffset();
				func.name = currentFunction.getName();
				func.calls = currentFunction.getCalledFunctions(monitor).stream()// .filter(f -> !f.isExternal())
						.map(f -> f.getEntryPoint().getOffset()).collect(Collectors.toList());
				// func.api = currentFunction.getCallingFunctions(monitor).stream().filter(f ->
				// f.isExternal())
				// .map(f -> f.getName()).collect(Collectors.toList());
				func.addr_end = currentFunction.getBody().getMaxAddress().getOffset();

				CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocksContaining(currentFunction.getBody(),
						monitor);
				while (codeBlockIterator.hasNext()) {
					CodeBlock codeBlock = codeBlockIterator.next();

					Block block = new Block();
					block.addr_f = func.addr_start;
					block.addr_start = codeBlock.getFirstStartAddress().getOffset();
					block.name = codeBlock.getName();
					model.blocks.add(block);
					func.bbs_len += 1;

					CodeBlockReferenceIterator codeBlockReferenceDestsIterator = codeBlock.getDestinations(monitor);
					while (codeBlockReferenceDestsIterator.hasNext()) {
						CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
						CodeBlock codeBlockDest = codeBlockReference.getDestinationBlock();
						block.calls.add(codeBlockDest.getFirstStartAddress().getOffset());
					}

					Listing listing = program.getListing();
					CodeUnitIterator codeUnitIterator = listing.getCodeUnits(codeBlock, true);
					while (codeUnitIterator.hasNext()) {
						CodeUnit cu = codeUnitIterator.next();
						if (cu instanceof Instruction) {
							Instruction instr = (Instruction) cu;
							Ins ins = new Ins();
							ins.ea = instr.getAddress().getOffset();
							ins.mne = instr.getMnemonicString();
							for (int i = 0; i < instr.getNumOperands(); ++i) {
								ins.oprs.add(format.getOperandRepresentationString(cu, i));
								ins.oprs_tp.add(instr.getPrototype().getOpType(i, instr.getInstructionContext()));
							}

							for (Reference rf : instr.getReferencesFrom()) {
								Long offset = rf.getToAddress().getOffset();
								if (dataMap.containsKey(offset))
									ins.dr.add(offset);

								Function calledFunction = functionManager.getFunctionContaining(rf.getToAddress());
								if (calledFunction != null) {
									ins.cr.add(rf.getToAddress().getOffset());
								}
							}

							block.ins.add(ins);
						}
					}
				}

				if (func.bbs_len > 0)
					model.functions.add(func);
			}
			model.comments = ParseComments(program, cursorFunction, functionManager);
			return model;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static List<Comment> ParseComments(Program program, Function cursorFunction, FunctionManager functionManager) {
		List<Comment> comments = new ArrayList<>();
		ArrayList<Pair<Integer, Integer>> comment_category_map = new ArrayList<>();
		comment_category_map.add(new Pair<>(0, CodeUnit.PRE_COMMENT));
		comment_category_map.add(new Pair<>(1, CodeUnit.POST_COMMENT));
		comment_category_map.add(new Pair<>(3, CodeUnit.PLATE_COMMENT));
		comment_category_map.add(new Pair<>(2, CodeUnit.REPEATABLE_COMMENT));

		Listing listing = program.getListing();
		for (Pair<Integer, Integer> p : comment_category_map) {
			int comment_category = p.second;
			int comment_type = p.first;

			AddressIterator forward_comment_itr = listing.getCommentAddressIterator(comment_category,
					program.getMemory(), true);

			while (forward_comment_itr.hasNext()) {
				Address address = forward_comment_itr.next();
				
				if (cursorFunction != null){
					Function currentFunction =  functionManager.getFunctionContaining(address);
					if (currentFunction == null || !cursorFunction.getEntryPoint().equals(currentFunction.getEntryPoint()))
						continue;
				}
				
				String content = listing.getComment(comment_category, address);

				// Can return null comments for some reason? Weird.
				if (content == null)
					continue;

				Comment comment = new Comment();
				comment.category = comment_type;
				comment.content = content;
				// This assumes simple block model so no overlap is possible
				comment.address = address.getOffset();
				// CodeBlock block_containing_comment =
				// basicBlockModel.getFirstCodeBlockContaining(address,
				// TaskMonitor.DUMMY);

				// comment.blk = block_containing_comment == null ? -1 :
				// block_containing_comment.getFirstStartAddress().getOffset();
				comment.author = "Ghidra";
				comment.created_at = date_formatter.format(Calendar.getInstance().getTime());

				Function function = program.getFunctionManager().getFunctionContaining(address);
				if (function != null) {
					comment.address = address.getOffset();
					comment.func = function.getEntryPoint().getOffset();
					comments.add(comment);
				}
			}
		}

		return comments;

	}

}