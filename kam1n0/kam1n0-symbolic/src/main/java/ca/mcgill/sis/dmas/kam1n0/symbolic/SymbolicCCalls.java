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
package ca.mcgill.sis.dmas.kam1n0.symbolic;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.commons.lang.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BitVecNum;
import com.microsoft.z3.Context;

import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

/**
 * Implementing ccalls referring to the Angr implementation.
 * 
 * @author dingm
 *
 */
public class SymbolicCCalls {

	private static Logger logger = LoggerFactory.getLogger(SymbolicCCalls.class);

	private static HashMap<String, CCallProperty> map;

	public static interface CCallFunction {
		public SimNode calculate(Z3Box box, TypeInformation type, List<SimNode> args);
	}

	private static HashMap<String, CCallFunction> callees = new HashMap<>();

	public static boolean implemented(String name) {
		return callees.containsKey(name);
	}

	static {
		// X86
		callees.put("x86g_calculate_condition", SymbolicCCalls::_x86g_calculate_condition);
		callees.put("x86g_calculate_eflags_all", SymbolicCCalls::_x86g_calculate_eflags_all);
		callees.put("x86g_calculate_eflags_c", SymbolicCCalls::_x86g_calculate_eflags_c);
		callees.put("x86g_calculate_RCR", SymbolicCCalls::_x86g_calculate_RCR);
		callees.put("x86g_check_fldcw", SymbolicCCalls::_x86g_check_fldcw);
		callees.put("x86g_calculate_daa_das_aaa_aas", SymbolicCCalls::_x86g_calculate_daa_das_aaa_aas);
		callees.put("x86g_create_fpucw", SymbolicCCalls::_x86g_create_fpucw);
		callees.put("x86g_calculate_RCL", SymbolicCCalls::_x86g_calculate_RCL);
		callees.put("x86g_calculate_mmx_psadbw", SymbolicCCalls::_x86g_calculate_mmx_psadbw);
		callees.put("convert_f64le_to_f80le_64", SymbolicCCalls::convert_f64le_to_f80le_64);
		callees.put("convert_f64le_to_f80le_16", SymbolicCCalls::convert_f64le_to_f80le_16);
		callees.put("convert_f64le_to_f80le", SymbolicCCalls::convert_f64le_to_f80le);

		// AMD64
		callees.put("amd64g_calculate_rflags_c", SymbolicCCalls::_amd64g_amd64g_calculate_rflags_c);
		callees.put("amd64g_calculate_condition", SymbolicCCalls::_amd64g_calculate_condition);
		callees.put("amd64g_calculate_rflags_all", SymbolicCCalls::_amd64g_calculate_rflags_all);
		callees.put("amd64g_check_ldmxcsr", SymbolicCCalls::_amd64g_check_ldmxcsr);
		callees.put("amd64g_create_mxcsr", SymbolicCCalls::_amd64g_create_mxcsr);

		// ARM
		callees.put("armg_calculate_condition", SymbolicCCalls::_armg_calculate_condition);
		callees.put("armg_calculate_data_nzcv", SymbolicCCalls::_armg_calculate_data_nzcv);
		callees.put("armg_calculate_flag_c", SymbolicCCalls::_armg_calculate_flag_c);
		callees.put("armg_calculate_flag_n", SymbolicCCalls::_armg_calculate_flag_n);
		callees.put("armg_calculate_flag_v", SymbolicCCalls::_armg_calculate_flag_v);
		callees.put("armg_calculate_flag_z", SymbolicCCalls::_armg_calculate_flag_z);

		// ARM64
		callees.put("arm64g_calculate_condition", SymbolicCCalls::_arm64g_calculate_condition);
		callees.put("arm64g_calculate_data_nzcv", SymbolicCCalls::_arm64g_calculate_data_nzcv);
		callees.put("arm64g_calculate_flag_c", SymbolicCCalls::_arm64g_calculate_flag_c);
		callees.put("arm64g_calculate_flag_n", SymbolicCCalls::_arm64g_calculate_flag_n);
		callees.put("arm64g_calculate_flag_v", SymbolicCCalls::_arm64g_calculate_flag_v);
		callees.put("arm64g_calculate_flag_z", SymbolicCCalls::_arm64g_calculate_flag_z);
	}

	private static class CCallProperty {
		public HashMap<Integer, String> CondTypes;
		public HashMap<String, Integer> CondTypesRev;
		public HashMap<String, Integer> CondBitOffsets;
		public HashMap<String, Long> CondBitMasks;
		public HashMap<Integer, String> OpTypes;
		public HashMap<String, Integer> OpTypesRev;
		public Integer size;
	}

	public static void load(InputStream stream) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			TypeReference<HashMap<String, CCallProperty>> typeRef = new TypeReference<HashMap<String, CCallProperty>>() {
			};
			map = mapper.readValue(stream, typeRef);
		} catch (Exception e) {
			logger.error("Failed to load operation attribute map.", e);
		}
	}

	public static void main(String[] args) throws FileNotFoundException {
		load(new FileInputStream(new File("D:\\Git\\Kam1n0\\kam1n0-symbolic\\scripts\\maps.ccall.json")));
		System.out.println();
		System.loadLibrary("libz3");

		Z3Box box = new Z3Box(new Context(), VexArchitectureType.VexArchX86, "");

		System.out.println(Long.toBinaryString(getMask(box, "X86", "CC_MASK_P")));
		System.out.println(
				Long.toBinaryString(box.concretizeValue(getDataMask(box, SimNode.val(box.ctx, 16l, 64), 64), true)));
		System.out.println(
				Long.toBinaryString(box.concretizeValue(getSignMask(box, SimNode.val(box.ctx, 16l, 64), 64), true)));
		System.out.println(Long.toBinaryString(
				box.concretizeValue(SimNode.val(box.ctx, 16l, 64).bitAt(SimNode.val(box.ctx, 5l, 64)), true)));
	}

	public static SimNode call(String calleeName, Z3Box box, TypeInformation type, List<SimNode> args) {
		CCallFunction callee = callees.get(calleeName);
		if (callee == null) {
			// logger.info("Unsupported ccall {}. Overwrite result with zero.", calleeName);
			return SimNode.zero(box.ctx, type.outputType.numOfBit());
		} else
			return callee.calculate(box, type, args);
	}

	private static long getMask(Z3Box box, String guest, String maskId) {
		return map.get(guest).CondBitMasks.get(maskId);
	}

	private static int getOffset(String guest, String offsetId) {
		return map.get(guest).CondBitOffsets.get(offsetId);
	}

	public static class FlagMetaPC {

		// all of 0x0000.......[1/0] format
		public SimNode cf;
		public SimNode pf;
		public SimNode af;
		public SimNode zf;
		public SimNode sf;
		public SimNode of;

		private String guest;

		public FlagMetaPC(Z3Box box, String guest) {
			this.guest = guest;
		}

		public FlagMetaPC(Z3Box box, SimNode cc, String guest) {
			this.guest = guest;
			cc.zeroExtend(map.get(guest).size);
			cf = cc.and(getMask(box, guest, "CC_MASK_C")).shr(getOffset(guest, "CC_SHIFT_C"));
			pf = cc.and(getMask(box, guest, "CC_MASK_P")).shr(getOffset(guest, "CC_SHIFT_P"));
			af = cc.and(getMask(box, guest, "CC_MASK_A")).shr(getOffset(guest, "CC_SHIFT_A"));
			zf = cc.and(getMask(box, guest, "CC_MASK_Z")).shr(getOffset(guest, "CC_SHIFT_Z"));
			sf = cc.and(getMask(box, guest, "CC_MASK_S")).shr(getOffset(guest, "CC_SHIFT_S"));
			of = cc.and(getMask(box, guest, "CC_MASK_O")).shr(getOffset(guest, "CC_SHIFT_O"));
		}

		public SimNode merge() {
			return cf.zeroExtend(map.get(guest).size).shl(getOffset(guest, "CC_SHIFT_C"))
					.or(pf.zeroExtend(map.get(guest).size).shl(getOffset(guest, "CC_SHIFT_P")))
					.or(af.zeroExtend(map.get(guest).size).shl(getOffset(guest, "CC_SHIFT_A")))
					.or(zf.zeroExtend(map.get(guest).size).shl(getOffset(guest, "CC_SHIFT_Z")))
					.or(sf.zeroExtend(map.get(guest).size).shl(getOffset(guest, "CC_SHIFT_S")))
					.or(of.zeroExtend(map.get(guest).size).shl(getOffset(guest, "CC_SHIFT_O")));

		}

		private SimNode formalize(SimNode node, int bits) {
			if (node.size() > bits) {
				return node.extract(bits - 1, 0);
			} else if (node.size() < bits) {
				return node.zeroExtend(bits);
			}
			return node;
		}

		/**
		 * fill enough zeros.
		 * 
		 * @return
		 */
		public FlagMetaPC formalize() {
			int pszie = map.get(guest).size;
			cf = formalize(cf, pszie);
			pf = formalize(pf, pszie);
			af = formalize(af, pszie);
			zf = formalize(zf, pszie);
			sf = formalize(sf, pszie);
			of = formalize(of, pszie);
			return this;
		}
	}

	private static SimNode getBitsFromOpration(Z3Box box, SimNode opr, String guest) {
		int psize = map.get(guest).size;
		SimNode nbits = SimNode.zero(box.ctx, psize);
		if (guest.equals("X86")) {
			SimNode mod = opr.mod(3);
			nbits = box.createCondition(mod.cmpeq(1), SimNode.val(box.ctx, 8, psize), nbits);
			nbits = box.createCondition(mod.cmpeq(2), SimNode.val(box.ctx, 16, psize), nbits);
			nbits = box.createCondition(mod.cmpeq(0), SimNode.val(box.ctx, 32, psize), nbits);
		} else if (guest.equals("AMD64")) {
			SimNode mod = opr.mod(4);
			nbits = box.createCondition(mod.cmpeq(1), SimNode.val(box.ctx, 8, psize), nbits);
			nbits = box.createCondition(mod.cmpeq(2), SimNode.val(box.ctx, 16, psize), nbits);
			nbits = box.createCondition(mod.cmpeq(3), SimNode.val(box.ctx, 32, psize), nbits);
			nbits = box.createCondition(mod.cmpeq(4), SimNode.val(box.ctx, 64, psize), nbits);
		}
		// if (opr.endsWith("B"))
		// nbits = 8;
		// else if (opr.endsWith("W"))
		// nbits = 16;
		// else if (opr.endsWith("L"))
		// nbits = 32;
		// else if (opr.endsWith("Q"))
		// nbits = 64;
		return nbits;
	}

	private static SimNode getSignMask(Z3Box box, SimNode bits, int platformBits) {
		// return SimNode.val(box.ctx, 1 << (bits - 1), platformBits);
		return SimNode.one(box.ctx, platformBits).shl(bits.sub(1));
	}

	private static SimNode getDataMask(Z3Box box, SimNode bits, int platformBits) {
		// return SimNode.val(box.ctx, -1 >>> (32 - bits + 1), platformBits);//
		return SimNode.val(box.ctx, -1, platformBits).shr(bits.neg().add(platformBits + 1));
	}

	@SafeVarargs
	private static final FlagMetaPC symSwitchMetaFlag(Z3Box box, SimNode input, String guest,
			EntryPair<int[], Supplier<FlagMetaPC>>... conditions) {

		if (input.e.isNumeral()) {
			BitVecNum num = (BitVecNum) input.e;
			int val = num.getInt();
			Optional<EntryPair<int[], Supplier<FlagMetaPC>>> flagSupplier = Arrays.stream(conditions)
					.filter(cond -> ArrayUtils.contains(cond.key, val)).findAny();
			if (flagSupplier.isPresent()) {
				return flagSupplier.get().value.get();
			}
		}

		Map<Integer, FlagMetaPC> condFlagMap = Arrays.stream(conditions)
				.flatMap(ent -> Arrays.stream(ent.key)
						.mapToObj(key -> new EntryPair<Integer, Supplier<FlagMetaPC>>(new Integer(key), ent.value)))
				.filter(ent -> !ent.key.equals(-100)).collect(Collectors.toMap(ent -> ent.key, ent -> {
					FlagMetaPC val = ent.value.get();
					if (val == null) {
						logger.error("Found a null val for key {}", ent.key);
					}
					return val;
				}));

		Map<Integer, SimNode> cfMap = condFlagMap.entrySet().stream()
				.collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue().cf));
		Map<Integer, SimNode> pfMap = condFlagMap.entrySet().stream()
				.collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue().pf));
		Map<Integer, SimNode> afMap = condFlagMap.entrySet().stream()
				.collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue().af));
		Map<Integer, SimNode> zfMap = condFlagMap.entrySet().stream()
				.collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue().zf));
		Map<Integer, SimNode> sfMap = condFlagMap.entrySet().stream()
				.collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue().sf));
		Map<Integer, SimNode> ofMap = condFlagMap.entrySet().stream()
				.collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue().of));

		FlagMetaPC newFlag = new FlagMetaPC(box, guest);
		newFlag.cf = box.condition(cfMap, input, box.getDefaultValue());
		newFlag.pf = box.condition(pfMap, input, box.getDefaultValue());
		newFlag.af = box.condition(afMap, input, box.getDefaultValue());
		newFlag.zf = box.condition(zfMap, input, box.getDefaultValue());
		newFlag.sf = box.condition(sfMap, input, box.getDefaultValue());
		newFlag.of = box.condition(ofMap, input, box.getDefaultValue());

		return newFlag;
	}

	private static SimNode calculateParity(SimNode res, int platformBits) {
		int psize = res.size();
		if (res.size() > 7) {
			psize = 7;
		}

		// use result size instead.
		SimNode b = SimNode.one(res.ctx, res.size());
		for (int i = 0; i < psize; ++i)
			b = b.or(res.bitAt(i));

		return b;
	}

	private static SimNode calculateZeroBit(SimNode res, int platformBits) {
		return new SimNode(res.ctx,
				(BitVecExpr) res.ctx.mkITE(res.ctx.mkEq(res.e, SimNode.zero(res.ctx, res.size()).e),
						SimNode.one(res.ctx, platformBits).e, SimNode.zero(res.ctx, platformBits).e),
				VexVariableType.getIntType(platformBits));
	}

	private static FlagMetaPC calculate_flag_metapc(Z3Box box, SimNode opr, SimNode cc_dep1, SimNode cc_dep2,
			SimNode cc_formal, String guest) {

		final SimNode bitsUsed = getBitsFromOpration(box, opr, guest);

		return symSwitchMetaFlag(box, opr, guest, //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_COPY")//
				}, () -> {
					// (zero OR all masks) & cc_dep1
					cc_dep1.zeroExtend(map.get(guest).size);
					List<Long> masks = map.get(guest).CondBitMasks.keySet().stream()
							.map(maskId -> getMask(box, guest, maskId)).collect(Collectors.toList());
					SimNode zero = SimNode.zero(box.ctx, map.get(guest).size);
					for (Long mask : masks) {
						zero = zero.or(mask);
					}
					return new FlagMetaPC(box, zero, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_ADDB"), //
						map.get(guest).OpTypesRev.get("CC_OP_ADDW"), //
						map.get(guest).OpTypesRev.get("CC_OP_ADDL"), //
						map.get(guest).OpTypesRev.get("CC_OP_ADDQ") //
				}, () -> {
					return metapc_add(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_ADCB"), //
						map.get(guest).OpTypesRev.get("CC_OP_ADCW"), //
						map.get(guest).OpTypesRev.get("CC_OP_ADCL"), //
						map.get(guest).OpTypesRev.get("CC_OP_ADCQ") //
				}, () -> {
					return metapc_adc(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_SUBB"), //
						map.get(guest).OpTypesRev.get("CC_OP_SUBW"), //
						map.get(guest).OpTypesRev.get("CC_OP_SUBL"), //
						map.get(guest).OpTypesRev.get("CC_OP_SUBQ") //
				}, () -> {
					return metapc_sub(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_SBBB"), //
						map.get(guest).OpTypesRev.get("CC_OP_SBBW"), //
						map.get(guest).OpTypesRev.get("CC_OP_SBBL"), //
						map.get(guest).OpTypesRev.get("CC_OP_SBBQ") //
				}, () -> {
					return metapc_sbb(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_LOGICB"), //
						map.get(guest).OpTypesRev.get("CC_OP_LOGICW"), //
						map.get(guest).OpTypesRev.get("CC_OP_LOGICL"), //
						map.get(guest).OpTypesRev.get("CC_OP_LOGICQ") //
				}, () -> {
					return metapc_logic(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_INCB"), //
						map.get(guest).OpTypesRev.get("CC_OP_INCW"), //
						map.get(guest).OpTypesRev.get("CC_OP_INCL"), //
						map.get(guest).OpTypesRev.get("CC_OP_INCQ") //
				}, () -> {
					return metapc_inc(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_DECB"), //
						map.get(guest).OpTypesRev.get("CC_OP_DECW"), //
						map.get(guest).OpTypesRev.get("CC_OP_DECL"), //
						map.get(guest).OpTypesRev.get("CC_OP_DECQ") //
				}, () -> {
					return metapc_dec(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_SHLB"), //
						map.get(guest).OpTypesRev.get("CC_OP_SHLW"), //
						map.get(guest).OpTypesRev.get("CC_OP_SHLL"), //
						map.get(guest).OpTypesRev.get("CC_OP_SHLQ") //
				}, () -> {
					return metapc_shl(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_SHRB"), //
						map.get(guest).OpTypesRev.get("CC_OP_SHRW"), //
						map.get(guest).OpTypesRev.get("CC_OP_SHRL"), //
						map.get(guest).OpTypesRev.get("CC_OP_SHRQ") //
				}, () -> {
					return metapc_shr(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_ROLB"), //
						map.get(guest).OpTypesRev.get("CC_OP_ROLW"), //
						map.get(guest).OpTypesRev.get("CC_OP_ROLL"), //
						map.get(guest).OpTypesRev.get("CC_OP_ROLQ") //
				}, () -> {
					return metapc_rol(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_RORB"), //
						map.get(guest).OpTypesRev.get("CC_OP_RORW"), //
						map.get(guest).OpTypesRev.get("CC_OP_RORL"), //
						map.get(guest).OpTypesRev.get("CC_OP_RORQ") //
				}, () -> {
					return metapc_ror(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_UMULB"), //
						map.get(guest).OpTypesRev.get("CC_OP_UMULW"), //
						map.get(guest).OpTypesRev.get("CC_OP_UMULL"), //
						map.get(guest).OpTypesRev.get("CC_OP_UMULQ"), //
				}, () -> {
					return metapc_umul(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}), //
				// new EntryPair<>(new int[] { //
				// map.get(guest).OpTypesRev.get("CC_OP_UMULQ"), //
				// }, () -> {
				// return metapc_umulq(box, bitsUsed, cc_dep1, cc_dep2,
				// cc_formal, guest);
				// }), //
				new EntryPair<>(new int[] { //
						map.get(guest).OpTypesRev.get("CC_OP_SMULB"), //
						map.get(guest).OpTypesRev.get("CC_OP_SMULW"), //
						map.get(guest).OpTypesRev.get("CC_OP_SMULL"), //
						map.get(guest).OpTypesRev.get("CC_OP_SMULQ") //
				}, () -> {
					return metapc_smul(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
				}) //
		// new EntryPair<>(new int[] { //
		// map.get(guest).OpTypesRev.get("CC_OP_SMULQ"), //
		// }, () -> {
		// return metapc_smulq(box, bitsUsed, cc_dep1, cc_dep2, cc_formal,
		// guest);
		// }) //
		);

		// if (in(opr, "CC_OP_ADDB", "CC_OP_ADDW", "CC_OP_ADDL", "CC_OP_ADDQ"))
		// return metapc_add(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_ADCB", "CC_OP_ADCW", "CC_OP_ADCL", "CC_OP_ADCQ"))
		// return metapc_adc(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_SUBB", "CC_OP_SUBW", "CC_OP_SUBL", "CC_OP_SUBQ"))
		// return metapc_sub(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_SBBB", "CC_OP_SBBW", "CC_OP_SBBL", "CC_OP_SBBQ"))
		// return metapc_sbb(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_LOGICB", "CC_OP_LOGICW", "CC_OP_LOGICL",
		// "CC_OP_LOGICQ"))
		// return metapc_logic(box, bitsUsed, cc_dep1, cc_dep2, cc_formal,
		// guest);
		//
		// if (in(opr, "CC_OP_INCB", "CC_OP_INCW", "CC_OP_INCL", "CC_OP_INCQ"))
		// return metapc_inc(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_DECB", "CC_OP_DECW", "CC_OP_DECL", "CC_OP_DECQ"))
		// return metapc_dec(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_SHLB", "CC_OP_SHLW", "CC_OP_SHLL", "CC_OP_SHLQ"))
		// return metapc_shl(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_SHRB", "CC_OP_SHRW", "CC_OP_SHRL", "CC_OP_SHRQ"))
		// return metapc_shr(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_ROLB", "CC_OP_ROLW", "CC_OP_ROLL", "CC_OP_ROLQ"))
		// return metapc_rol(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_RORB", "CC_OP_RORW", "CC_OP_RORL", "CC_OP_RORQ"))
		// return metapc_ror(box, bitsUsed, cc_dep1, cc_dep2, cc_formal, guest);
		//
		// if (in(opr, "CC_OP_UMULB", "CC_OP_UMULW", "CC_OP_UMULL",
		// "CC_OP_UMULQ"))
		// return metapc_umul(box, bitsUsed, cc_dep1, cc_dep2, cc_formal,
		// guest);
		//
		// if (in(opr, "CC_OP_UMULQ"))
		// return metapc_umulq(box, bitsUsed, cc_dep1, cc_dep2, cc_formal,
		// guest);
		//
		// if (in(opr, "CC_OP_SMULB", "CC_OP_SMULW", "CC_OP_SMULL",
		// "CC_OP_SMULQ"))
		// return metapc_smul(box, bitsUsed, cc_dep1, cc_dep2, cc_formal,
		// guest);
		//
		// if (in(opr, "CC_OP_SMULQ"))
		// return metapc_smulq(box, bitsUsed, cc_dep1, cc_dep2, cc_formal,
		// guest);

		// logger.error("Unknown operation {}", opr);
		// return null;
	}

	public static SimNode calculate_flag_metapc_c(Z3Box box, SimNode opr, SimNode cc_dep1, SimNode cc_dep2,
			SimNode cc_formal, String guest) {
		// int psize = map.get(guest).size;
		// if (opr.equalsIgnoreCase("CC_OP_COPY")) {
		// return
		// cc_dep1.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).zeroExtend(psize);
		// } else if (in(opr, "G_CC_OP_LOGICQ", "G_CC_OP_LOGICL",
		// "G_CC_OP_LOGICW", "G_CC_OP_LOGICB")) {
		// return SimNode.zero(box.ctx, psize);
		// }
		FlagMetaPC flag = calculate_flag_metapc(box, opr, cc_dep1, cc_dep2, cc_formal, guest);
		return flag.cf;
	}

	private static FlagMetaPC metapc_add(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;
		SimNode signMask = getSignMask(box, bits, psize);
		SimNode dataMask = getDataMask(box, bits, psize);

		SimNode res = cc_dep1.add(cc_dep2);

		flag.cf = box.createCondition(res.cmplt(cc_dep1, false), SimNode.one(box.ctx, psize),
				SimNode.zero(box.ctx, psize));
		flag.pf = calculateParity(res, psize);
		flag.af = res.xor(cc_dep1).xor(cc_dep2).bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = calculateZeroBit(res, psize);
		flag.sf = res.and(signMask).bitAt(bits.sub(1));
		flag.of = ((cc_dep1.xor(cc_dep2).xor(dataMask)).and(cc_dep1.xor(res))).and(signMask).bitAt(bits.sub(1));

		return flag.formalize();
	}

	private static FlagMetaPC metapc_sub(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;
		SimNode signMask = getSignMask(box, bits, psize);

		SimNode res = cc_dep1.sub(cc_dep2);
		flag.cf = box.createCondition(cc_dep1.cmplt(cc_dep2, false), SimNode.one(box.ctx, psize),
				SimNode.zero(box.ctx, psize));
		flag.pf = calculateParity(res, psize);
		flag.af = res.xor(cc_dep1).xor(cc_dep2).bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = calculateZeroBit(res, psize);
		flag.sf = res.and(signMask).bitAt(bits.sub(1));
		flag.of = ((cc_dep1.xor(cc_dep2)).and(cc_dep1.xor(res))).and(signMask).bitAt(bits.sub(1));

		return flag.formalize();
	}

	private static FlagMetaPC metapc_logic(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;
		SimNode signMask = getSignMask(box, bits, psize);

		flag.cf = SimNode.zero(box.ctx, psize);
		flag.pf = calculateParity(cc_dep1, psize);
		flag.af = SimNode.zero(box.ctx, psize);
		flag.zf = calculateZeroBit(cc_dep1, psize);
		flag.sf = cc_dep1.and(signMask).bitAt(bits.sub(1));
		flag.of = SimNode.zero(box.ctx, psize);

		return flag.formalize();
	}

	private static FlagMetaPC metapc_dec(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;
		SimNode signMask = getSignMask(box, bits, psize);

		SimNode arg1 = cc_dep1.add(SimNode.one(box.ctx, cc_dep1.size()));
		SimNode arg2 = SimNode.one(box.ctx, cc_dep1.size());

		flag.cf = cc_formal.and(getMask(box, guest, "CC_MASK_C"))
				.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_C"));
		flag.pf = calculateParity(cc_dep1, psize);
		flag.af = cc_dep1.xor(arg1).xor(arg2).bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = calculateZeroBit(cc_dep1, psize);
		flag.sf = cc_dep1.and(signMask).bitAt(bits.sub(1));
		flag.of = box.createCondition(flag.sf.cmpeq(arg1.bitAt(bits.sub(1))), SimNode.zero(box.ctx, psize),
				SimNode.one(box.ctx, psize));

		return flag.formalize();
	}

	private static FlagMetaPC metapc_adc(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;

		SimNode old_c = cc_formal.and(map.get(guest).CondBitMasks.get("CC_MASK_C"));
		// .extract(bits - 1, 0);
		SimNode arg1 = cc_dep1;
		SimNode arg2 = cc_dep2.xor(old_c);
		SimNode res = arg1.add(arg2).add(old_c);

		flag.cf = box.createCondition(//
				old_c.cmpnez(), //
				box.createCondition(res.cmple(arg1, false), SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize)), //
				box.createCondition(res.cmplt(arg1, false), SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize)));

		flag.pf = calculateParity(res, psize);
		flag.af = res.xor(arg1).xor(arg2).bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = calculateZeroBit(res, psize);
		flag.sf = res.bitAt(bits.sub(1));
		flag.of = (arg1.xor(arg2).xor(-1)).and(arg1.xor(res)).bitAt(0);

		return flag.formalize();
	}

	private static FlagMetaPC metapc_sbb(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;

		SimNode old_c = cc_formal.and(map.get(guest).CondBitMasks.get("CC_MASK_C"));
		SimNode arg1 = cc_dep1;
		SimNode arg2 = cc_dep2.xor(old_c);
		SimNode res = arg1.sub(arg2).sub(old_c);

		flag.cf = box.createCondition(arg1.cmple(arg2, false), SimNode.one(box.ctx, psize),
				SimNode.zero(box.ctx, psize));
		SimNode cf_noc = box.createCondition(arg1.cmplt(arg2, false), SimNode.one(box.ctx, psize),
				SimNode.zero(box.ctx, psize));
		flag.cf = box.createCondition(old_c.cmpeq(SimNode.one(box.ctx, old_c.size())), flag.cf, cf_noc);
		flag.pf = calculateParity(res, psize);
		flag.af = res.xor(arg1).xor(arg2).bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = calculateZeroBit(res, psize);
		flag.sf = res.bitAt(bits.sub(1));
		flag.of = (arg1.xor(arg2)).and(arg1.xor(res)).bitAt(bits.sub(1));

		return flag.formalize();
	}

	private static FlagMetaPC metapc_inc(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;
		SimNode signMask = getSignMask(box, bits, psize);

		SimNode arg1 = cc_dep1.sub(SimNode.one(box.ctx, cc_dep1.size()));
		SimNode arg2 = SimNode.one(box.ctx, cc_dep1.size());

		flag.cf = cc_formal.and(getMask(box, guest, "CC_MASK_C"))
				.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_C"));
		flag.pf = calculateParity(cc_dep1, psize);
		flag.af = cc_dep1.xor(arg1).xor(arg2).bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = calculateZeroBit(cc_dep1, psize);
		flag.sf = cc_dep1.and(signMask).bitAt(bits.sub(1));
		flag.of = box.createCondition(flag.sf.cmpeq(arg1.bitAt(bits.sub(1))), SimNode.zero(box.ctx, psize),
				SimNode.one(box.ctx, psize));

		return flag.formalize();
	}

	private static FlagMetaPC metapc_shl(Z3Box box, SimNode bits, SimNode remaining, SimNode shifted, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;
		flag.cf = remaining.shr(bits.sub(1)).bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_C"));
		flag.pf = calculateParity(remaining.extract(7, 0), psize);
		flag.af = SimNode.zero(box.ctx, psize);
		flag.zf = calculateZeroBit(remaining, psize);
		flag.sf = remaining.bitAt(bits.sub(1));
		flag.of = remaining.bitAt(0).xor(shifted.bitAt(0)).bitAt(0);
		return flag.formalize();
	}

	private static FlagMetaPC metapc_shr(Z3Box box, SimNode bits, SimNode remaining, SimNode shifted, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;
		flag.cf = box.createCondition(shifted.bitAt(0).cmpnez(), SimNode.one(box.ctx, psize),
				SimNode.zero(box.ctx, psize));
		flag.pf = calculateParity(remaining.extract(7, 0), psize);
		flag.af = SimNode.zero(box.ctx, psize);
		flag.zf = calculateZeroBit(remaining, psize);
		flag.sf = remaining.bitAt(bits.sub(1));
		flag.of = remaining.bitAt(0).xor(shifted.bitAt(0)).bitAt(0);
		return flag.formalize();
	}

	private static FlagMetaPC metapc_rol(Z3Box box, SimNode bits, SimNode res, SimNode unused, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		flag.cf = res.bitAt(0);
		flag.pf = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_P"));
		flag.af = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z"));
		flag.sf = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_S"));
		flag.of = res.shr(bits.sub(1)).xor(res).bitAt(0);
		return flag.formalize();
	}

	private static FlagMetaPC metapc_ror(Z3Box box, SimNode bits, SimNode res, SimNode unused, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		flag.cf = res.bitAt(bits.sub(1));
		flag.pf = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_P"));
		flag.af = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_A"));
		flag.zf = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z"));
		flag.sf = cc_formal.bitAt(map.get(guest).CondBitOffsets.get("CC_SHIFT_S"));
		flag.of = res.bitAt(bits.sub(1)).xor(res.bitAt(bits.sub(1)));
		return flag.formalize();
	}

	private static FlagMetaPC metapc_umul(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;

		SimNode lo = cc_dep1.mul(cc_dep2).extract(bits.sub(1), 0);
		SimNode rr = lo;
		SimNode hi = rr.shr(bits).extract(bits.sub(1), 0);

		flag.cf = box.createCondition(hi.cmpnez(), SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));
		flag.pf = calculateParity(lo, psize);
		flag.af = SimNode.zero(box.ctx, psize);
		flag.zf = calculateZeroBit(lo, psize);
		flag.sf = lo.bitAt(bits.sub(1));
		flag.of = flag.cf;
		return flag.formalize();
	}

	private static FlagMetaPC metapc_umulq(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		logger.error("Unsupported UMULQ operation. Returning zero flags");
		return new FlagMetaPC(box, SimNode.zero(box.ctx, map.get(guest).size), guest);
	}

	private static FlagMetaPC metapc_smul(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		FlagMetaPC flag = new FlagMetaPC(box, guest);
		int psize = map.get(guest).size;

		SimNode lo = cc_dep1.mul(cc_dep2).extract(bits.sub(1), 0);
		SimNode rr = lo;
		SimNode hi = rr.shr(bits).extract(bits.sub(1), 0);

		flag.cf = box.createCondition(hi.cmpne(lo.shr(bits.sub(1))), SimNode.one(box.ctx, psize),
				SimNode.zero(box.ctx, psize));
		flag.pf = calculateParity(lo, psize);
		flag.af = SimNode.zero(box.ctx, psize);
		flag.zf = calculateZeroBit(lo, psize);
		flag.sf = lo.bitAt(bits.sub(1));
		flag.of = flag.cf;
		return flag.formalize();
	}

	private static FlagMetaPC metapc_smulq(Z3Box box, SimNode bits, SimNode cc_dep1, SimNode cc_dep2, SimNode cc_formal,
			String guest) {
		logger.error("Unsupported UMULQ operation. Returning zero flags");
		return new FlagMetaPC(box, SimNode.zero(box.ctx, map.get(guest).size), guest);
	}

	public static SimNode calculateConditionX86AMD64(Z3Box box, String guest, SimNode cond, SimNode cc_op,
			SimNode cc_dep1, SimNode cc_dep2, SimNode cc_ndep) {

		// Integer condv = box.concretizeValue(cond).intValue();
		// Integer oprv = box.concretizeValue(cc_op).intValue();
		// String condstr = map.get(guest).CondTypes.get(condv);
		// String oprstr = map.get(guest).OpTypes.get(oprv);
		//
		// assert condstr != null;
		// assert oprstr != null;

		FlagMetaPC flag = calculate_flag_metapc(box, cc_op, cc_dep1, cc_dep2, cc_ndep, guest);

		assert flag != null;

		int psize = map.get(guest).size;
		SimNode t_inv = cond.bitAt(0);
		if (t_inv.size() < psize)
			t_inv = t_inv.zeroExtend(psize);
		else
			t_inv = t_inv.extract(psize - 1, 0);
		SimNode inv = t_inv;
		SimNode result = box.symSwitchMultiKey(cond, box.getDefaultValue(), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondBE"), //
						map.get(guest).CondTypesRev.get("CondNBE") //
				}, () -> {
					return inv.xor(flag.cf.or(flag.zf)).bitAt(0);
				}), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondLE"), //
						map.get(guest).CondTypesRev.get("CondNLE") //
				}, () -> {
					return inv.xor(flag.zf.or(flag.sf.xor(flag.of))).bitAt(0);
				}), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondL"), //
						map.get(guest).CondTypesRev.get("CondNL") //
				}, () -> {
					return inv.xor(flag.sf.xor(flag.of)).bitAt(0);
				}), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondO"), //
						map.get(guest).CondTypesRev.get("CondNO") //
				}, () -> {
					return inv.xor(flag.of).bitAt(0);
				}), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondZ"), //
						map.get(guest).CondTypesRev.get("CondNZ") //
				}, () -> {
					return inv.xor(flag.zf).bitAt(0);
				}), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondB"), //
						map.get(guest).CondTypesRev.get("CondNB") //
				}, () -> {
					return inv.xor(flag.cf).bitAt(0);
				}), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondS"), //
						map.get(guest).CondTypesRev.get("CondNS") //
				}, () -> {
					return inv.xor(flag.sf).bitAt(0);
				}), //
				new EntryPair<>(new Integer[] { //
						map.get(guest).CondTypesRev.get("CondP"), //
						map.get(guest).CondTypesRev.get("CondNP") //
				}, () -> {
					return inv.xor(flag.pf).bitAt(0);
				})//
		);

		// if (condstr.contains("BE")) {
		// result = inv.xor(flag.cf.or(flag.zf)).bitAt(0);
		// } else if (condstr.contains("LE")) {
		// result = inv.xor(flag.zf.or(flag.sf.xor(flag.of))).bitAt(0);
		// } else if (condstr.contains("L")) {
		// result = inv.xor(flag.sf.xor(flag.of)).bitAt(0);
		// } else {
		// if (condstr.contains("O"))
		// result = inv.xor(flag.of).bitAt(0);
		// else if (condstr.contains("Z"))
		// result = inv.xor(flag.zf).bitAt(0);
		// else if (condstr.contains("B"))
		// result = inv.xor(flag.cf).bitAt(0);
		// else if (condstr.contains("S"))
		// result = inv.xor(flag.sf).bitAt(0);
		// else if (condstr.contains("P"))
		// result = inv.xor(flag.pf).bitAt(0);
		// }

		assert result != null;
		return result.zeroExtend(psize);
	}

	// x86 ccalls

	public static SimNode _x86g_calculate_condition(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 5;
		return calculateConditionX86AMD64(box, "X86", args.get(0), args.get(1), args.get(2), args.get(3), args.get(4));
	}

	public static SimNode _x86g_calculate_eflags_all(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 4;
		String guest = "X86";
		return calculate_flag_metapc(box, args.get(0), args.get(1), args.get(1), args.get(2), guest).merge();

	}

	public static SimNode _x86g_calculate_eflags_c(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 4;
		String guest = "X86";
		return calculate_flag_metapc_c(box, args.get(0), args.get(1), args.get(1), args.get(2), guest);
	}

	public static SimNode _x86g_check_fldcw(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() > 0;
		return args.get(0).shr(10).and(3).zeroExtend(32);
	}

	public static SimNode _x86g_create_fpucw(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() > 0;
		return args.get(0).and(3).shl(10).and(0x037f).zeroExtend(32);
	}

	public static SimNode _x86g_calculate_RCR(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 4;
		SimNode arg = args.get(0).zeroExtend(64);
		SimNode rot_amt = args.get(1);
		SimNode eflags_in = args.get(2).zeroExtend(64);
		Long sz = args.get(3).getAnyVal();
		Long tmpCOUNT = rot_amt.getAnyVal() & 0x1f;
		String guest = "X86";

		assert sz != null;
		assert tmpCOUNT != null;

		SimNode cf;
		SimNode of;

		if (sz == 4) {
			cf = eflags_in.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
			of = arg.shr(31).xor(cf).bitAt(0);
			while (tmpCOUNT > 0) {
				SimNode tempcf = arg.and(1);
				arg = arg.shr(1).or(cf.shl(31));
				cf = tempcf;
				tmpCOUNT--;
			}
		} else if (sz == 2) {
			while (tmpCOUNT >= 17)
				tmpCOUNT -= 17;
			cf = eflags_in.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
			of = arg.shr(15).xor(cf).bitAt(0);
			while (tmpCOUNT > 0) {
				SimNode tempcf = arg.bitAt(0);
				arg = arg.shr(1).and(0x7fff).or(cf.shl(15));
				cf = tempcf;
				tmpCOUNT--;
			}
		} else if (sz == 1) {
			while (tmpCOUNT >= 9)
				tmpCOUNT -= 9;
			cf = eflags_in.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
			of = arg.shr(7).xor(cf).bitAt(0);
			while (tmpCOUNT > 0) {
				SimNode tempcf = arg.bitAt(0);
				arg = arg.shr(1).and(0x7f).or(cf.shl(7));
				cf = tempcf;
				tmpCOUNT--;
			}
		} else {
			logger.error("Unsupported sz value of " + sz);
			return null;
		}

		cf = cf.bitAt(0);
		of = of.bitAt(0);
		eflags_in = eflags_in.and(~(map.get(guest).CondBitMasks.get("CC_MASK_C").intValue()
				| map.get(guest).CondBitMasks.get("CC_MASK_O").intValue()));
		eflags_in = eflags_in.or(//
				cf.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_C"))//
						.or(of.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_O")))//
		);

		// eflags_in is 64bits long
		// logger.info("Expected output type of ccall x86g_calculate_RCR: " +
		// type.toString());
		return eflags_in.shl(32).or(arg);// .extract(63, 64 / 2);

	}

	public static SimNode _x86g_calculate_RCL(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 4;
		SimNode arg = args.get(0).zeroExtend(64);
		SimNode rot_amt = args.get(1);
		SimNode eflags_in = args.get(2).zeroExtend(64);
		Long sz = args.get(3).getAnyVal();
		Long tmpCOUNT = rot_amt.getAnyVal() & 0x1f;
		String guest = "X86";

		assert sz != null;
		assert tmpCOUNT != null;

		SimNode cf;
		SimNode of;

		if (sz == 4) {
			cf = eflags_in.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
			of = arg.shr(31).xor(cf).bitAt(0);
			while (tmpCOUNT > 0) {
				SimNode tempcf = arg.shr(31).and(1);
				arg = arg.shl(1).or(cf.and(1));
				cf = tempcf;
				tmpCOUNT--;
			}
		} else if (sz == 2) {
			while (tmpCOUNT >= 17)
				tmpCOUNT -= 17;
			cf = eflags_in.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
			of = arg.shr(15).xor(cf).bitAt(0);
			while (tmpCOUNT > 0) {
				SimNode tempcf = arg.shr(15).and(1);
				arg = arg.shl(1).or(cf.and(1)).and(0xffff);
				cf = tempcf;
				tmpCOUNT--;
			}
		} else if (sz == 1) {
			while (tmpCOUNT >= 9)
				tmpCOUNT -= 9;
			cf = eflags_in.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
			of = arg.shr(7).xor(cf).bitAt(0);
			while (tmpCOUNT > 0) {
				SimNode tempcf = arg.shr(7).and(1);
				arg = arg.shl(1).or(cf.and(1)).and(0xff);
				cf = tempcf;
				tmpCOUNT--;
			}
		} else {
			logger.error("Unsupported sz value of " + sz);
			return null;
		}

		cf = cf.bitAt(0);
		of = of.bitAt(0);
		eflags_in = eflags_in.and(~(map.get(guest).CondBitMasks.get("CC_MASK_C").intValue()
				| map.get(guest).CondBitMasks.get("CC_MASK_O").intValue()));
		eflags_in = eflags_in.or(//
				cf.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_C"))//
						.or(of.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_O")))//
		);

		// eflags_in is 64bits long
		// logger.info("Expected output type of ccall x86g_calculate_RCR: " +
		// type.toString());
		return eflags_in.shl(32).or(arg);// .extract(63, 64 / 2);

	}

	public static SimNode _x86g_calculate_daa_das_aaa_aas(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 2;
		SimNode flags_and_AX = args.get(0);
		SimNode opcode = args.get(0);
		String guest = "X86";
		int psize = map.get(guest).size;

		FlagMetaPC flag = new FlagMetaPC(box, flags_and_AX.shr(16), guest);

		// (flags_and_AX >> 0) & 0xFF;
		SimNode r_AL = flags_and_AX.shr(0).and(0xff);

		// (flags_and_AX >> 8) & 0xFF;
		SimNode r_AH = flags_and_AX.shr(8).and(0xff);

		flags_and_AX = box.symSwitchMultiKey(opcode, flags_and_AX, //
				new EntryPair<>(new Integer[] { 0x27 }, () -> {
					FlagMetaPC nflag = new FlagMetaPC(box, guest);
					SimNode n_AL = r_AL;

					SimNode cond1 = r_AL.and(0xf).cmpgt(9, false).or(flag.af.cmpeq(1));
					n_AL = cond1.ite(n_AL.add(6), n_AL);
					nflag.cf = cond1.ite(flag.cf, SimNode.zero(box.ctx, psize));
					nflag.cf = cond1.and(n_AL.cmpge(0x100, false)).ite(SimNode.one(box.ctx, psize), nflag.cf);
					nflag.af = cond1.ite(SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));

					SimNode cond2 = r_AL.cmpgt(0x99, false).or(flag.cf.cmpeq(1));
					n_AL = cond2.ite(n_AL.add(0x60), n_AL);
					nflag.cf = cond2.ite(SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));

					n_AL = n_AL.and(0xff);
					nflag.of = SimNode.zero(box.ctx, psize);
					nflag.sf = n_AL.and(0x80).cmpne(0).ite(1, 0);
					nflag.zf = n_AL.cmpeq(0).ite(1, 0);
					nflag.pf = calculateParity(n_AL, psize);

					return nflag.merge().shl(16).or(r_AH.and(0xff).shl(8)).or(n_AL.and(0xff));
				}), //
				new EntryPair<>(new Integer[] { 0x2f }, () -> {
					FlagMetaPC nflag = new FlagMetaPC(box, guest);
					SimNode n_AL = r_AL;

					SimNode cond1 = r_AL.and(0xf).cmpgt(9, false).or(flag.af.cmpeq(1));
					n_AL = cond1.ite(n_AL.sub(6), n_AL);
					nflag.cf = cond1.ite(flag.cf, SimNode.zero(box.ctx, psize));
					nflag.cf = cond1.and(r_AL.cmplt(6, false)).ite(SimNode.one(box.ctx, psize), nflag.cf);
					nflag.af = cond1.ite(SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));

					SimNode cond2 = r_AL.cmpgt(0x99, false).or(flag.cf.cmpeq(1));
					n_AL = cond2.ite(n_AL.sub(0x60), n_AL);
					nflag.cf = cond2.ite(SimNode.one(box.ctx, psize), nflag.cf);

					n_AL = n_AL.and(0xff);
					nflag.of = SimNode.zero(box.ctx, psize);
					nflag.sf = n_AL.and(0x80).cmpne(0).ite(1, 0);
					nflag.zf = n_AL.cmpeq(0).ite(1, 0);
					nflag.pf = calculateParity(n_AL, psize);

					return nflag.merge().shl(16).or(r_AH.and(0xff).shl(8)).or(n_AL.and(0xff));
				}), //
				new EntryPair<>(new Integer[] { 0x37 }, () -> {
					FlagMetaPC nflag = new FlagMetaPC(box, guest);
					SimNode n_AL = r_AL;
					SimNode n_AH = r_AH;

					SimNode cond1 = r_AL.and(0xf).cmpgt(9, false).or(flag.af.cmpeq(1));
					n_AL = cond1.ite(n_AL.add(6), n_AL);
					n_AH = cond1.and(r_AL.cmpgt(0xf9, false)).ite(n_AH.add(2), n_AH.add(1));
					n_AL = n_AL.and(0xf);

					nflag.cf = cond1.ite(SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));
					nflag.af = cond1.ite(SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));

					nflag.of = SimNode.zero(box.ctx, psize);
					nflag.sf = SimNode.zero(box.ctx, psize);
					nflag.zf = SimNode.zero(box.ctx, psize);
					nflag.pf = SimNode.zero(box.ctx, psize);

					return nflag.merge().shl(16).or(n_AH.and(0xff).shl(8)).or(n_AL.and(0xff));

				}), //
				new EntryPair<>(new Integer[] { 0x3f }, () -> {
					FlagMetaPC nflag = new FlagMetaPC(box, guest);
					SimNode n_AL = r_AL;
					SimNode n_AH = r_AH;

					SimNode cond1 = r_AL.and(0xf).cmpgt(9, false).or(flag.af.cmpeq(1));
					n_AL = cond1.ite(n_AL.sub(6), n_AL);
					n_AH = cond1.and(r_AL.cmplt(0x06, false)).ite(n_AH.sub(2), n_AH.sub(1));
					n_AL = n_AL.and(0xf);

					nflag.cf = cond1.ite(SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));
					nflag.af = cond1.ite(SimNode.one(box.ctx, psize), SimNode.zero(box.ctx, psize));

					nflag.of = SimNode.zero(box.ctx, psize);
					nflag.sf = SimNode.zero(box.ctx, psize);
					nflag.zf = SimNode.zero(box.ctx, psize);
					nflag.pf = SimNode.zero(box.ctx, psize);

					return nflag.merge().shl(16).or(n_AH.and(0xff).shl(8)).or(n_AL.and(0xff));
				})//
		);

		return flags_and_AX;

	}

	public static SimNode _x86g_calculate_mmx_psadbw(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode arg0 = args.get(0).zeroExtend(128);
		SimNode arg1 = args.get(0).zeroExtend(128);
		SimNode sum = SimNode.zero(box.ctx, arg0.size());
		for (int i = 0; i < 8; ++i) {
			sum.add(arg0.extract((i + 1) * 8 - 1, i * 8).add(arg1.extract((i + 1) * 8 - 1, i * 8)));
		}
		return sum.and(0xffff).extract(63, 0);
	}

	public static SimNode convert_f64le_to_f80le_64(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode data = args.get(0);
		SimNode exponent = data.extract(62, 52);
		SimNode mantissa = data.extract(51, 0);

		SimNode normalized_mantissa = SimNode.one(box.ctx, 1).concate(mantissa).concate(SimNode.zero(box.ctx, 11));
		SimNode zero_mantissa = SimNode.zero(box.ctx, 64);
		SimNode inf_mantissa = SimNode.val(box.ctx, -1l, 64);
		return exponent.cmpeq(0).ite(//
				zero_mantissa, exponent.cmpeq(-1).ite(//
						mantissa.cmpeq(0).ite(zero_mantissa, inf_mantissa), //
						normalized_mantissa));
	}

	public static SimNode convert_f64le_to_f80le_16(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode data = args.get(0);
		SimNode sign = data.bitAt(63).extract(0, 0);
		SimNode exponent = data.extract(62, 52);

		SimNode normalized_exponent = exponent.zeroExtend(15).sub(1023).add(16383);
		SimNode zero_exponent = SimNode.zero(box.ctx, 15);
		SimNode inf_exponent = SimNode.val(box.ctx, -1, 15);
		return sign.concate(//
				exponent.cmpeq(0).ite(//
						zero_exponent, //
						exponent.cmpeq(-1).ite(//
								inf_exponent, //
								normalized_exponent)));
	}

	public static SimNode convert_f64le_to_f80le(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode d16 = args.get(0);
		SimNode d64 = args.get(1);

		SimNode sign = d16.bitAt(15).extract(0, 0);
		SimNode exponent = d16.extract(14, 0);
		SimNode mantissa = d64.extract(62, 0);

		SimNode normalized_exponent = exponent.extract(10, 0).sub(16383).add(1023);
		SimNode zero_exponent = SimNode.zero(box.ctx, 11);
		SimNode inf_exponent = SimNode.val(box.ctx, -1, 11);
		SimNode final_exponent = exponent.cmpeq(0).ite(//
				zero_exponent, //
				exponent.cmpeq(-1).ite(//
						inf_exponent, //
						normalized_exponent));

		SimNode normalized_mantissa = d64.extract(62, 11);
		SimNode zero_mantissa = SimNode.zero(box.ctx, 52);
		SimNode inf_mantissa = SimNode.val(box.ctx, -1l, 52);
		SimNode final_mantissa = exponent.cmpeq(0).ite(//
				zero_mantissa, exponent.cmpeq(-1).ite(//
						mantissa.cmpeq(0).ite(zero_mantissa, inf_mantissa), //
						normalized_mantissa));

		return sign.concate(final_exponent).concate(final_mantissa);

	}

	public static SimNode get_segdescr_base(Z3Box box, SimNode discriptor) {
		SimNode lo = discriptor.extract(31, 16);
		SimNode mid = discriptor.extract(39, 32);
		SimNode hi = discriptor.extract(63, 56);
		return SimNode.concate(box.ctx, hi, mid, lo);
	}

	public static SimNode get_segdescr_limit(Z3Box box, SimNode discriptor) {
		SimNode granularity = discriptor.bitAt(55);
		SimNode lo = discriptor.extract(15, 0);
		SimNode hi = discriptor.extract(51, 48);
		SimNode limit = SimNode.concate(box.ctx, hi, lo).zeroExtend(32);
		return granularity.cmpeq(0).ite(limit, limit.shl(12).or(0xfff));
	}

	// amd64 ccalls

	public static SimNode _amd64g_calculate_condition(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 5;
		return calculateConditionX86AMD64(box, "AMD64", args.get(0), args.get(1), args.get(2), args.get(3),
				args.get(4));
	}

	public static SimNode _amd64g_calculate_rflags_all(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 4;
		String guest = "AMD64";
		return calculate_flag_metapc(box, args.get(0), args.get(1), args.get(1), args.get(2), guest).merge();
	}

	public static SimNode _amd64g_amd64g_calculate_rflags_c(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() == 4;
		String guest = "AMD64";
		return calculate_flag_metapc_c(box, args.get(0), args.get(1), args.get(1), args.get(2), guest);
	}

	public static SimNode _amd64g_create_mxcsr(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() > 0;
		return args.get(0).and(3).shl(13).and(0x1F80);
	}

	public static SimNode _amd64g_check_ldmxcsr(Z3Box box, TypeInformation type, List<SimNode> args) {
		assert args.size() > 0;
		SimNode rmode = args.get(0).shr(13).and(3);
		SimNode ew = box.createCondition(//
				args.get(0).and(0x1F80).cmpne(0x1F80), //
				SimNode.val(box.ctx, 3, 64), //
				box.createCondition(//
						args.get(0).and(1 << 15).cmpnez(), //
						SimNode.val(box.ctx, 4, 64), //
						box.createCondition(//
								args.get(0).and(1 << 6).cmpnez(), //
								SimNode.val(box.ctx, 5, 64), //
								SimNode.val(box.ctx, 0, 64)//
						)//
				)//
		);//

		return ew.shl(32).or(rmode);
	}

	// arm

	// private static int[] parseCondOprForArm(int val) {
	// int cond = val >>> 4;
	// int opr = val & 0xF;
	// return new int[] { cond, opr };
	// }

	private static SimNode parseCond(SimNode val) {
		return val.shr(4).and(0xF);
	}

	private static SimNode parseOpr(SimNode val) {
		return val.and(0xF);
	}

	public static SimNode _armg_calculate_data_nzcv(Z3Box box, TypeInformation type, List<SimNode> args) {

		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		String guest = "ARM";

		SimNode n = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
		SimNode z = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
		SimNode c = _armg_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
		SimNode v = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));

		return //
		(n.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_N"))).or//
		(z.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z"))).or//
		(c.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_C"))).or//
		(v.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_V"))); //
	}

	public static SimNode _armg_calculate_condition(Z3Box box, TypeInformation type, List<SimNode> args) {

		assert args.size() == 4;
		String guest = "ARM";

		// int[] vals =
		// parseCondOprForArm(box.concretizeValue(args.get(0)).intValue());
		// assert vals != null && vals.length == 2;
		//
		// String cond = map.get(guest).CondTypes.get(vals[0]);
		// int inv = vals[0] & 1;
		// int psize = map.get(guest).size;
		// SimNode cc_op = SimNode.val(box.ctx, vals[1], psize);

		int psize = map.get(guest).size;

		SimNode cc_op = parseOpr(args.get(0));
		SimNode cond = parseCond(args.get(0));
		SimNode inv = cond.bitAt(0);

		SimNode cc_dep1 = args.get(1).zeroExtend(psize);
		SimNode cc_dep2 = args.get(2).zeroExtend(psize);
		SimNode cc_dep3 = args.get(3).zeroExtend(psize);

		SimNode flag = box.symSwitch(cond, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondAL"), () -> {//
					return SimNode.one(box.ctx, psize);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondEQ"), () -> {//
					SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return zf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondNE"), () -> {//
					SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return zf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondHS"), () -> {//
					SimNode cf = _armg_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondLO"), () -> {//
					SimNode cf = _armg_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondMI"), () -> {//
					SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondPL"), () -> {//
					SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondVS"), () -> {//
					SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return vf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondVC"), () -> {//
					SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return vf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondHI"), () -> {//
					SimNode cf = _armg_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.and(zf.not()).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondLS"), () -> {//
					SimNode cf = _armg_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.and(zf.not()).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondGE"), () -> {//
					SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).not().bitAt(0).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondLT"), () -> {//
					SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).not().bitAt(0).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondGT"), () -> {//
					SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).or(zf).not().bitAt(0).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondLE"), () -> {//
					SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).or(zf).not().bitAt(0).xor(inv);
				}));

		return flag.zeroExtend(psize);

		// if (in(cond, "ARMCondAL")) {
		// flag = SimNode.one(box.ctx, psize);
		// } else if (in(cond, "ARMCondEQ", "ARMCondNE")) {
		// SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = zf.xor(inv);
		// } else if (in(cond, "ARMCondHS", "ARMCondLO")) {
		// SimNode cf = _armg_calculate_flag_c(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = cf.xor(inv);
		// } else if (in(cond, "ARMCondMI", "ARMCondPL")) {
		// SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = nf.xor(inv);
		// } else if (in(cond, "ARMCondVS", "ARMCondVC")) {
		// SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = vf.xor(inv);
		// } else if (in(cond, "ARMCondHI", "ARMCondLS")) {
		// SimNode cf = _armg_calculate_flag_c(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// System.out.println(cf.size());
		// System.out.println(zf.size());
		// flag = cf.and(zf.not()).xor(inv);
		// } else if (in(cond, "ARMCondGE", "ARMCondLT")) {
		// SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = nf.xor(vf).not().bitAt(0).xor(inv);
		// } else if (in(cond, "ARMCondGT", "ARMCondLE")) {
		// SimNode nf = _armg_calculate_flag_n(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode vf = _armg_calculate_flag_v(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode zf = _armg_calculate_flag_z(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = nf.xor(vf).or(zf).not().bitAt(0).xor(inv);
		// }
		//
		// if (flag == null) {
		// logger.error("Condition {} not supported in
		// _armg_calculate_condition.", cond);
		// return null;
		// } else

	}

	public static SimNode _armg_calculate_flag_v(Z3Box box, TypeInformation type, List<SimNode> args) {

		SimNode flag = null;
		String guest = "ARM";

		assert args.size() == 4;
		// String cc_op =
		// map.get(guest).OpTypes.get(box.concretizeValue(args.get(0)).intValue());
		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_V")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBB"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC"), () -> {
					return cc_dep3;
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MUL"), () -> {
					return cc_dep3.bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MULL"), () -> {
					return cc_dep3.bitAt(0);
				})//
		);

		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_V")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_SUB")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_ADC")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_SBB")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_LOGIC")) {
		// flag = cc_dep3;
		// } else if (cc_op.equals("CC_OP_MUL")) {
		// flag = cc_dep3.bitAt(0);
		// } else if (cc_op.equals("CC_OP_MULL")) {
		// flag = cc_dep3.bitAt(0);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in armg_calculate_flag_v", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

	public static SimNode _armg_calculate_flag_n(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode flag = null;
		String guest = "ARM";

		assert args.size() == 4;
		// String cc_op =
		// map.get(guest).OpTypes.get(box.concretizeValue(args.get(0)).intValue());
		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_N")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBB"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC"), () -> {
					return cc_dep1.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MUL"), () -> {
					return cc_dep1.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MULL"), () -> {
					return cc_dep2.shr(31);
				})//
		);

		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_N")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_SUB")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_ADC")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_SBB")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_LOGIC")) {
		// flag = cc_dep1.shr(31);
		// } else if (cc_op.equals("CC_OP_MUL")) {
		// flag = cc_dep1.shr(31);
		// } else if (cc_op.equals("CC_OP_MULL")) {
		// flag = cc_dep2.shr(31);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in armg_calculate_flag_n", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

	public static SimNode _armg_calculate_flag_c(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode flag = null;
		String guest = "ARM";

		assert args.size() == 4;
		// String cc_op =
		// map.get(guest).OpTypes.get(box.concretizeValue(args.get(0)).intValue());
		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return res.cmplt(cc_dep1, false);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB"), () -> {
					return cc_dep1.cmpge(cc_dep2, false);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return box.createCondition(cc_dep2.cmpnez(), res.cmple(cc_dep1, false), res.cmplt(cc_dep1, false));
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBB"), () -> {
					return box.createCondition(cc_dep2.cmpnez(), cc_dep1.cmpge(cc_dep2, false),
							cc_dep1.cmpgt(cc_dep2, false));
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC"), () -> {
					return cc_dep2;
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MUL"), () -> {
					return cc_dep3.shr(1).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MULL"), () -> {
					return cc_dep3.shr(1).bitAt(0);
				})//
		);
		//
		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// flag = res.cmplt(cc_dep1, false);
		// } else if (cc_op.equals("CC_OP_SUB")) {
		// flag = cc_dep1.cmpge(cc_dep2, false);
		// } else if (cc_op.equals("CC_OP_ADC")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// flag = box.condition(cc_dep2.cmpnez(), res.cmple(cc_dep1, false),
		// res.cmplt(cc_dep1, false));
		// } else if (cc_op.equals("CC_OP_SBB")) {
		// flag = box.condition(cc_dep2.cmpnez(), cc_dep1.cmpge(cc_dep2, false),
		// cc_dep1.cmpgt(cc_dep2, false));
		// } else if (cc_op.equals("CC_OP_LOGIC")) {
		// flag = cc_dep2;
		// } else if (cc_op.equals("CC_OP_MUL")) {
		// flag = cc_dep3.shr(1).bitAt(0);
		// } else if (cc_op.equals("CC_OP_MULL")) {
		// flag = cc_dep3.shr(1).bitAt(0);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in armg_calculate_flag_c", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

	public static SimNode _armg_calculate_flag_z(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode flag = null;
		String guest = "ARM";
		int psize = map.get(guest).size;

		assert args.size() == 4;
		// String cc_op =
		// map.get(guest).OpTypes.get(box.concretizeValue(args.get(0)).intValue());
		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBB"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC"), () -> {
					return calculateZeroBit(cc_dep1, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MUL"), () -> {
					return calculateZeroBit(cc_dep1, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_MULL"), () -> {
					return calculateZeroBit(cc_dep1.or(cc_dep2), psize);
				})//
		);

		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_SUB")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_ADC")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_SBB")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_LOGIC")) {
		// flag = calculateZeroBit(cc_dep1, psize);
		// } else if (cc_op.equals("CC_OP_MUL")) {
		// flag = calculateZeroBit(cc_dep1, psize);
		// } else if (cc_op.equals("CC_OP_MULL")) {
		// flag = calculateZeroBit(cc_dep1.or(cc_dep2), psize);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in armg_calculate_flag_z", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

	// arm 64

	public static SimNode _arm64g_calculate_data_nzcv(Z3Box box, TypeInformation type, List<SimNode> args) {

		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		String guest = "ARM64";

		SimNode n = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
		SimNode z = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
		SimNode c = _arm64g_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
		SimNode v = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));

		return //
		(n.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_N"))).or//
		(z.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z"))).or//
		(c.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_C"))).or//
		(v.shl(map.get(guest).CondBitOffsets.get("CC_SHIFT_V"))); //
	}

	public static SimNode _arm64g_calculate_condition(Z3Box box, TypeInformation type, List<SimNode> args) {

		assert args.size() == 4;
		String guest = "ARM64";

		// int[] vals =
		// parseCondOprForArm(box.concretizeValue(args.get(0)).intValue());
		// assert vals != null && vals.length == 2;
		//
		// String cond = map.get(guest).CondTypes.get(vals[0]);
		// int inv = vals[0] & 1;
		// int psize = map.get(guest).size;
		// SimNode cc_op = SimNode.val(box.ctx, vals[1], psize);

		int psize = map.get(guest).size;

		SimNode cc_op = parseOpr(args.get(0));
		SimNode cond = parseCond(args.get(0));
		SimNode inv = cond.bitAt(0);

		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		SimNode flag = box.symSwitch(cond, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARMCondAL"), () -> {//
					return SimNode.zero(box.ctx, psize);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondNV"), () -> {//
					return SimNode.zero(box.ctx, psize);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondEQ"), () -> {//
					SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return zf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondNE"), () -> {//
					SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return zf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondCS"), () -> {//
					SimNode cf = _arm64g_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondCC"), () -> {//
					SimNode cf = _arm64g_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondMI"), () -> {//
					SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondPL"), () -> {//
					SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondVS"), () -> {//
					SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return vf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondVC"), () -> {//
					SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return vf.xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondHI"), () -> {//
					SimNode cf = _arm64g_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.and(zf.not()).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondLS"), () -> {//
					SimNode cf = _arm64g_calculate_flag_c(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return cf.and(zf.not()).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondGE"), () -> {//
					SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).not().bitAt(0).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondLT"), () -> {//
					SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).not().bitAt(0).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondGT"), () -> {//
					SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).or(zf).not().bitAt(0).xor(inv);
				}), //
				new EntryPair<>(map.get(guest).CondTypesRev.get("ARM64CondLE"), () -> {//
					SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op, cc_dep1, cc_dep2, cc_dep3));
					return nf.xor(vf).or(zf).not().bitAt(0).xor(inv);
				}));

		return flag.zeroExtend(psize);

		// if (in(cond, "ARMCondAL", "ARM64CondNV")) {
		// flag = SimNode.zero(box.ctx, psize);
		// } else if (in(cond, "ARM64CondEQ", "ARM64CondNE")) {
		// SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = zf.xor(inv);
		// } else if (in(cond, "ARM64CondCS", "ARM64CondCC")) {
		// SimNode cf = _arm64g_calculate_flag_c(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = cf.xor(inv);
		// } else if (in(cond, "ARM64CondMI", "ARM64CondPL")) {
		// SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = nf.xor(inv);
		// } else if (in(cond, "ARM64CondVS", "ARM64CondVC")) {
		// SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = vf.xor(inv);
		// } else if (in(cond, "ARM64CondHI", "ARM64CondLS")) {
		// SimNode cf = _arm64g_calculate_flag_c(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = cf.and(zf.not()).xor(inv);
		// } else if (in(cond, "ARM64CondGE", "ARM64CondLT")) {
		// SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = nf.xor(vf).not().bitAt(0).xor(inv);
		// } else if (in(cond, "ARM64CondGT", "ARM64CondLE")) {
		// SimNode nf = _arm64g_calculate_flag_n(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode vf = _arm64g_calculate_flag_v(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// SimNode zf = _arm64g_calculate_flag_z(box, type, Arrays.asList(cc_op,
		// cc_dep1, cc_dep2, cc_dep3));
		// flag = nf.xor(vf).or(zf).not().bitAt(0).xor(inv);
		// }
		//
		// if (flag == null) {
		// logger.error("Condition {} not supported in
		// _arm64g_calculate_condition.", cond);
		// return null;
		// } else
		// return flag.zeroExtend(psize);

	}

	public static SimNode _arm64g_calculate_flag_v(Z3Box box, TypeInformation type, List<SimNode> args) {

		SimNode flag = null;
		String guest = "ARM64";

		assert args.size() == 4;
		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_V")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
					return v.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB32"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB64"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
					return v.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
					return v.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC32"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
					return v.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC64"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
					return v.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC32"), () -> {
					return SimNode.zero(box.ctx, map.get(guest).size);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC64"), () -> {
					return SimNode.zero(box.ctx, map.get(guest).size);
				})//
		);

		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_V")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD32")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_ADD64")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
		// flag = v.shr(63);
		// } else if (cc_op.equals("CC_OP_SUB32")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_SUB64")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
		// flag = v.shr(63);
		// } else if (cc_op.equals("CC_OP_ADC32")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_ADC64")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// SimNode v = res.xor(cc_dep1).and(res.xor(cc_dep2));
		// flag = v.shr(63);
		// } else if (cc_op.equals("CC_OP_SBC32")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
		// flag = v.shr(31);
		// } else if (cc_op.equals("CC_OP_SBC64")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// SimNode v = cc_dep1.xor(cc_dep2).and(res.xor(cc_dep1));
		// flag = v.shr(63);
		// } else if (in(cc_op, "CC_OP_LOGIC32", "CC_OP_LOGIC64")) {
		// flag = SimNode.zero(box.ctx, map.get(guest).size);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in arm64g_calculate_flag_v", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

	public static SimNode _arm64g_calculate_flag_n(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode flag = null;
		String guest = "ARM64";

		assert args.size() == 4;
		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_N")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return res.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB32"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB64"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					return res.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return res.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC32"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					return res.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC64"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					return res.shr(63);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC32"), () -> {
					return cc_dep1.shr(31);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC64"), () -> {
					return cc_dep1.shr(63);
				})//
		);
		//
		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_N")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD32")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_ADD64")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// flag = res.shr(63);
		// } else if (cc_op.equals("CC_OP_SUB32")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_SUB64")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// flag = res.shr(63);
		// } else if (cc_op.equals("CC_OP_ADC32")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_ADC64")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// flag = res.shr(63);
		// } else if (cc_op.equals("CC_OP_SBC32")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// flag = res.shr(31);
		// } else if (cc_op.equals("CC_OP_SBC64")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// flag = res.shr(63);
		// } else if (cc_op.equals("CC_OP_LOGIC32")) {
		// flag = cc_dep1.shr(31);
		// } else if (cc_op.equals("CC_OP_LOGIC64")) {
		// flag = cc_dep1.shr(63);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in arm64g_calculate_flag_n", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

	public static SimNode _arm64g_calculate_flag_c(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode flag = null;
		String guest = "ARM64";

		assert args.size() == 4;
		// String cc_op =
		// map.get(guest).OpTypes.get(box.concretizeValue(args.get(0)).intValue());
		SimNode cc_op = args.get(0);
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return res.cmplt(cc_dep1, false);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return res.cmplt(cc_dep1, false);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB32"), () -> {
					return cc_dep1.cmpge(cc_dep2, false);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB64"), () -> {
					return cc_dep1.cmpge(cc_dep2, false);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return box.createCondition(cc_dep2.cmpnez(), res.cmple(cc_dep1, false), res.cmplt(cc_dep1, false));
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return box.createCondition(cc_dep2.cmpnez(), res.cmple(cc_dep1, false), res.cmplt(cc_dep1, false));
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC32"), () -> {
					return box.createCondition(cc_dep2.cmpnez(), cc_dep1.cmpge(cc_dep2, false),
							cc_dep1.cmpgt(cc_dep2, false));
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC64"), () -> {
					return box.createCondition(cc_dep2.cmpnez(), cc_dep1.cmpge(cc_dep2, false),
							cc_dep1.cmpgt(cc_dep2, false));
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC32"), () -> {
					return SimNode.zero(box.ctx, map.get(guest).size);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC64"), () -> {
					return SimNode.zero(box.ctx, map.get(guest).size);
				})//
		);

		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_C")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD32") ||
		// cc_op.equals("CC_OP_ADD64")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// flag = res.cmplt(cc_dep1, false);
		// } else if (cc_op.equals("CC_OP_SUB32") ||
		// cc_op.equals("CC_OP_SUB64")) {
		// flag = cc_dep1.cmpge(cc_dep2, false);
		// } else if (cc_op.equals("CC_OP_ADC32") ||
		// cc_op.equals("CC_OP_ADC64")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// flag = box.condition(cc_dep2.cmpnez(), res.cmple(cc_dep1, false),
		// res.cmplt(cc_dep1, false));
		// } else if (cc_op.equals("CC_OP_SBC32") ||
		// cc_op.equals("CC_OP_SBC64")) {
		// flag = box.condition(cc_dep2.cmpnez(), cc_dep1.cmpge(cc_dep2, false),
		// cc_dep1.cmpgt(cc_dep2, false));
		// } else if (cc_op.equals("CC_OP_LOGIC32") ||
		// cc_op.equals("CC_OP_LOGIC64")) {
		// flag = SimNode.zero(box.ctx, map.get(guest).size);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in arm64g_calculate_flag_c", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

	public static SimNode _arm64g_calculate_flag_z(Z3Box box, TypeInformation type, List<SimNode> args) {
		SimNode flag = null;
		String guest = "ARM64";
		int psize = map.get(guest).size;

		assert args.size() == 4;
		// String cc_op =
		// map.get(guest).OpTypes.get(box.concretizeValue(args.get(0)).intValue());
		SimNode cc_dep1 = args.get(1);
		SimNode cc_dep2 = args.get(2);
		SimNode cc_dep3 = args.get(3);
		SimNode cc_op = args.get(0);

		flag = box.symSwitch(cc_op, box.getDefaultValue(), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_COPY"), () -> {
					return cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z")).bitAt(0);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADD64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB32"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SUB64"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC32"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_ADC64"), () -> {
					SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC32"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_SBC64"), () -> {
					SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
					return calculateZeroBit(res, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC32"), () -> {
					return calculateZeroBit(cc_dep1, psize);
				}), //
				new EntryPair<>(map.get(guest).OpTypesRev.get("CC_OP_LOGIC64"), () -> {
					return calculateZeroBit(cc_dep1, psize);
				})//
		);

		// if (cc_op.equals("CC_OP_COPY")) {
		// flag =
		// cc_dep1.shr(map.get(guest).CondBitOffsets.get("CC_SHIFT_Z")).bitAt(0);
		// } else if (cc_op.equals("CC_OP_ADD32") ||
		// cc_op.equals("CC_OP_ADD64")) {
		// SimNode res = cc_dep1.add(cc_dep2);
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_SUB32") ||
		// cc_op.equals("CC_OP_SUB64")) {
		// SimNode res = cc_dep1.sub(cc_dep2);
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_ADC32") ||
		// cc_op.equals("CC_OP_ADC64")) {
		// SimNode res = cc_dep1.add(cc_dep2).add(cc_dep3);
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_SBC32") ||
		// cc_op.equals("CC_OP_SBC64")) {
		// SimNode res = cc_dep1.sub(cc_dep2).sub(cc_dep3.xor(1));
		// flag = calculateZeroBit(res, psize);
		// } else if (cc_op.equals("CC_OP_LOGIC32") ||
		// cc_op.equals("CC_OP_LOGIC64")) {
		// flag = calculateZeroBit(cc_dep1, psize);
		// }

		if (flag == null) {
			logger.error("Operation {} not supported in arm64g_calculate_flag_z", cc_op);
			return null;
		}

		return flag.zeroExtend(map.get(guest).size);
	}

}
