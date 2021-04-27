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
package ca.mcgill.sis.dmas.kam1n0.vex.operation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.io.collection.EntryPair;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;

import static ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType.*;

public class VexOperationUtils {

	public static class UnsupportedVexOperation extends Exception {
		private static final long serialVersionUID = -4701318255903617309L;
	}

	private static Logger logger = LoggerFactory.getLogger(VexOperationUtils.class);
	private static Map<VexOperationType, Attribute> operationAttributeMap = null;

	public static Attribute attr(VexOperationType type) {
		Attribute att = operationAttributeMap.get(type);
		if (att == null)
			return null;
		return att.clone();
	}

	public static void init(InputStream stream) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			TypeReference<HashMap<VexOperationType, Attribute>> typeRef = new TypeReference<HashMap<VexOperationType, Attribute>>() {
			};
			operationAttributeMap = mapper.readValue(stream, typeRef);

		} catch (Exception e) {
			logger.error("Failed to load operation attribute map.", e);
		}
	}

	public static enum RoundingMode {
		RM, RP, RN, RZ;
		public static RoundingMode def() {
			return RM;
		}
	}

	public static class Attribute {
		public String name = null;
		public String _generic_name = null;
		public Integer _from_size = null;
		public String _from_side = null;
		public String _from_type = null;
		public String _from_signed = null;
		public Integer _to_size = null;
		public String _to_type = null;
		public String _to_signed = null;
		public String _conversion = null;
		public String _vector_size = null;
		public String _vector_signed = null;
		public String _vector_type = null;
		public String _vector_zero = null;
		public String _vector_count = null;
		public String _rounding_mode = null;

		public Attribute clone() {
			Attribute attribute = new Attribute();
			attribute.name = name;
			attribute._generic_name = _generic_name;
			attribute._from_size = _from_size;
			attribute._from_side = _from_side;
			attribute._from_type = _from_type;
			attribute._from_signed = _from_signed;
			attribute._to_size = _to_size;
			attribute._to_type = _to_type;
			attribute._to_signed = _to_signed;
			attribute._conversion = _conversion;
			attribute._vector_size = _vector_size;
			attribute._vector_signed = _vector_signed;
			attribute._vector_type = _vector_type;
			attribute._vector_zero = _vector_zero;
			attribute._vector_count = _vector_count;
			attribute._rounding_mode = _rounding_mode;
			return attribute;
		}

		private static HashSet<String> orderInsensitive = Sets.newHashSet("Abs", "Avg", "Add", "Max", "Min", "Mul",
				"Or", "And", "Xor");

		public boolean isOrderSensitive() {
			if (VexOperationType.valueOf(this.name).getTypeInfo().argType.size() == 1)
				return false;
			Optional<String> opt = orderInsensitive.stream().filter(key -> this.name.contains(key)).findAny();
			if (opt.isPresent())
				return false;
			return true;
		}

		public boolean _float = false;
		public boolean _supported = true;

		@JsonIgnore
		public boolean isConvertOnly() {
			return (_generic_name == null || _generic_name.equals("Q")) && _conversion != null;
		}

		@JsonIgnore
		public boolean isConvert() {
			return _conversion != null;
		}

		@JsonIgnore
		public boolean isConvertAs() {
			return isConvert() && _conversion.equalsIgnoreCase("as");
		}

		@JsonIgnore
		public boolean isFromSigned() {
			boolean from_signed = _from_signed != null && _from_signed.equalsIgnoreCase("S");
			return from_signed;
		}

		@JsonIgnore
		public boolean isToSigned() {
			boolean to_signed = _to_signed != null && _to_signed.equalsIgnoreCase("S");
			return to_signed;
		}

		@JsonIgnore
		public boolean isVSigned() {
			boolean vector_signed = _vector_signed != null && _vector_signed.equalsIgnoreCase("S");
			return vector_signed;
		}

		@JsonIgnore
		public boolean isSigned() {
			return isFromSigned() || isToSigned() || isVSigned();
		}

		@JsonIgnore
		public boolean isFromF() {
			return (_from_type != null && _from_type.equalsIgnoreCase("F"));
		}

		@JsonIgnore
		public boolean isToF() {
			return (_to_type != null && _to_type.equalsIgnoreCase("F"));
		}

		@JsonIgnore
		public boolean isVF() {
			return (_vector_type != null && _vector_type.equalsIgnoreCase("F"));
		}

		@JsonIgnore
		public boolean isF() {
			return _float || (_from_type != null && _from_type.equalsIgnoreCase("F"))
					|| (_to_type != null && _to_type.equalsIgnoreCase("F"))
					|| (_vector_type != null && _vector_type.equalsIgnoreCase("F"));
		}

		@JsonIgnore
		public boolean isD() {
			return (_from_type != null && _from_type.equalsIgnoreCase("D"))
					|| (_to_type != null && _to_type.equalsIgnoreCase("D"))
					|| (_vector_type != null && _vector_type.equalsIgnoreCase("D"));
		}

		@JsonIgnore
		public boolean isV() {
			return _vector_count != null;
		}

		@JsonIgnore
		public boolean isV0() {
			return _vector_zero != null;
		}

		@JsonIgnore
		public int getVSize() {
			if (_vector_size == null)
				return -1;
			else
				return Integer.parseInt(_vector_size);
		}

		@JsonIgnore
		public int getVCount() {
			if (_vector_size == null)
				return -1;
			else
				return Integer.parseInt(_vector_count);
		}

		@JsonIgnore
		public RoundingMode getRM() {
			if (_rounding_mode == null)
				return RoundingMode.def();
			RoundingMode mode = RoundingMode.valueOf(_rounding_mode.replaceAll("-", ""));
			if (mode == null)
				return RoundingMode.def();
			else
				return mode;
		}

		@Override
		public String toString() {
			try {
				return (new ObjectMapper()).writeValueAsString(this);
			} catch (JsonProcessingException e) {
				logger.error("Error converting attribut to string", e);
				return StringResources.STR_EMPTY;
			}
		}

		public VexVariableType getFromType(VexArchitectureType type) {

			// there are two locations for from type:
			// from side and vector side
			// if from side is not null we return the type info from `from side`
			// if from side is null we return the type info from `vector side`
			// we assume that at least one of them is non-null

			int size = _from_size == null ? (getVSize() == -1 ? type.defaultTypte().numOfBit() : getVSize())
					: _from_size;
			if (isFromF())
				return VexVariableType.getFltType(size);
			else if (_from_type == null && isVF())
				return VexVariableType.getFltType(size);
			else
				return VexVariableType.getIntType(size);
		}

		public VexVariableType getToType(VexArchitectureType type) {

			// there are two locations for to type:
			// to side and vector side

			int size = _to_size == null ? (getVSize() == -1 ? type.defaultTypte().numOfBit() : getVSize()) : _to_size;
			if (isToF()) {
				return VexVariableType.getFltType(size);
			} else
				return VexVariableType.getIntType(size);
		}

		public VexVariableType getVType(VexArchitectureType type) {
			int size = (getVSize() == -1 ? type.defaultTypte().numOfBit() : getVSize());
			if (isVF()) {
				return VexVariableType.getFltType(size);
			} else
				return VexVariableType.getIntType(size);
		}

	}

	public boolean valid = false;

	public static class VexOperationRunnable {

		VexOperationRunnable(VexOperationType opr) {
			Attribute attrs = operationAttributeMap.get(opr);
			if (attrs == null)
				return;
			Set<String> types = Sets.newHashSet(attrs._vector_type, attrs._from_type, attrs._to_type);
			if (types.contains("F") || types.contains("D")) {
				attrs._float = true;
				if (types.contains("D"))
					logger.error("BCD operations arent supported");
				throw new UnsupportedOperationException();
			} else
				attrs._float = false;

			// determine operations:

		}

	}

	public static class TypeInformation implements Serializable {
		private static final long serialVersionUID = -7466998460908638660L;
		public List<VexVariableType> argType = new ArrayList<>();
		public VexVariableType outputType;
		public boolean hasRM = false;

		public TypeInformation fixRM() {
			for (int i = 0; i < argType.size(); i++)
				if (argType.get(i).equals(Ity_INVALID)) {
					argType.set(i, Ity_I32); // add back i32 as rounding mode.
					hasRM = true;
					break;
				}
			return this;
		}

		@Override
		public String toString() {
			return outputType.shortString() + ":" + StringResources.JOINER_TOKEN_CSV
					.join(argType.stream().map(VexVariableType::shortString).collect(Collectors.toList())) + "";
		}
	}

	public static void main(String[] args) throws FileNotFoundException {
		init(new FileInputStream(new File("D:\\Git\\Kam1n0\\kam1n0-rep\\scripts\\maps.json")));
	}

	public static TypeInformation typeOfPrimop(VexOperationType op) {

		VexVariableType ity_RMode = VexVariableType.Ity_INVALID;

		switch (op) {
		case Iop_Add8:
		case Iop_Sub8:
		case Iop_Mul8:
		case Iop_Or8:
		case Iop_And8:
		case Iop_Xor8:
			return BINARY(Ity_I8, Ity_I8, Ity_I8);

		case Iop_Add16:
		case Iop_Sub16:
		case Iop_Mul16:
		case Iop_Or16:
		case Iop_And16:
		case Iop_Xor16:
			return BINARY(Ity_I16, Ity_I16, Ity_I16);

		case Iop_CmpORD32U:
		case Iop_CmpORD32S:
		case Iop_Add32:
		case Iop_Sub32:
		case Iop_Mul32:
		case Iop_Or32:
		case Iop_And32:
		case Iop_Xor32:
		case Iop_Max32U:
		case Iop_QAdd32S:
		case Iop_QSub32S:
		case Iop_Add16x2:
		case Iop_Sub16x2:
		case Iop_QAdd16Sx2:
		case Iop_QAdd16Ux2:
		case Iop_QSub16Sx2:
		case Iop_QSub16Ux2:
		case Iop_HAdd16Ux2:
		case Iop_HAdd16Sx2:
		case Iop_HSub16Ux2:
		case Iop_HSub16Sx2:
		case Iop_Add8x4:
		case Iop_Sub8x4:
		case Iop_QAdd8Sx4:
		case Iop_QAdd8Ux4:
		case Iop_QSub8Sx4:
		case Iop_QSub8Ux4:
		case Iop_HAdd8Ux4:
		case Iop_HAdd8Sx4:
		case Iop_HSub8Ux4:
		case Iop_HSub8Sx4:
		case Iop_Sad8Ux4:
			return BINARY(Ity_I32, Ity_I32, Ity_I32);

		case Iop_Add64:
		case Iop_Sub64:
		case Iop_Mul64:
		case Iop_Or64:
		case Iop_And64:
		case Iop_Xor64:
		case Iop_CmpORD64U:
		case Iop_CmpORD64S:
		case Iop_Avg8Ux8:
		case Iop_Avg16Ux4:
		case Iop_Add8x8:
		case Iop_Add16x4:
		case Iop_Add32x2:
		case Iop_Add32Fx2:
		case Iop_Sub32Fx2:
		case Iop_CmpEQ8x8:
		case Iop_CmpEQ16x4:
		case Iop_CmpEQ32x2:
		case Iop_CmpGT8Sx8:
		case Iop_CmpGT16Sx4:
		case Iop_CmpGT32Sx2:
		case Iop_CmpGT8Ux8:
		case Iop_CmpGT16Ux4:
		case Iop_CmpGT32Ux2:
		case Iop_CmpGT32Fx2:
		case Iop_CmpEQ32Fx2:
		case Iop_CmpGE32Fx2:
		case Iop_InterleaveHI8x8:
		case Iop_InterleaveLO8x8:
		case Iop_InterleaveHI16x4:
		case Iop_InterleaveLO16x4:
		case Iop_InterleaveHI32x2:
		case Iop_InterleaveLO32x2:
		case Iop_CatOddLanes8x8:
		case Iop_CatEvenLanes8x8:
		case Iop_CatOddLanes16x4:
		case Iop_CatEvenLanes16x4:
		case Iop_InterleaveOddLanes8x8:
		case Iop_InterleaveEvenLanes8x8:
		case Iop_InterleaveOddLanes16x4:
		case Iop_InterleaveEvenLanes16x4:
		case Iop_Perm8x8:
		case Iop_Max8Ux8:
		case Iop_Max16Ux4:
		case Iop_Max32Ux2:
		case Iop_Max8Sx8:
		case Iop_Max16Sx4:
		case Iop_Max32Sx2:
		case Iop_Max32Fx2:
		case Iop_Min32Fx2:
		case Iop_PwMax32Fx2:
		case Iop_PwMin32Fx2:
		case Iop_Min8Ux8:
		case Iop_Min16Ux4:
		case Iop_Min32Ux2:
		case Iop_Min8Sx8:
		case Iop_Min16Sx4:
		case Iop_Min32Sx2:
		case Iop_PwMax8Ux8:
		case Iop_PwMax16Ux4:
		case Iop_PwMax32Ux2:
		case Iop_PwMax8Sx8:
		case Iop_PwMax16Sx4:
		case Iop_PwMax32Sx2:
		case Iop_PwMin8Ux8:
		case Iop_PwMin16Ux4:
		case Iop_PwMin32Ux2:
		case Iop_PwMin8Sx8:
		case Iop_PwMin16Sx4:
		case Iop_PwMin32Sx2:
		case Iop_Mul8x8:
		case Iop_Mul16x4:
		case Iop_Mul32x2:
		case Iop_Mul32Fx2:
		case Iop_PolynomialMul8x8:
		case Iop_MulHi16Sx4:
		case Iop_MulHi16Ux4:
		case Iop_QDMulHi16Sx4:
		case Iop_QDMulHi32Sx2:
		case Iop_QRDMulHi16Sx4:
		case Iop_QRDMulHi32Sx2:
		case Iop_QAdd8Sx8:
		case Iop_QAdd16Sx4:
		case Iop_QAdd32Sx2:
		case Iop_QAdd64Sx1:
		case Iop_QAdd8Ux8:
		case Iop_QAdd16Ux4:
		case Iop_QAdd32Ux2:
		case Iop_QAdd64Ux1:
		case Iop_PwAdd8x8:
		case Iop_PwAdd16x4:
		case Iop_PwAdd32x2:
		case Iop_PwAdd32Fx2:
		case Iop_QNarrowBin32Sto16Sx4:
		case Iop_QNarrowBin16Sto8Sx8:
		case Iop_QNarrowBin16Sto8Ux8:
		case Iop_NarrowBin16to8x8:
		case Iop_NarrowBin32to16x4:
		case Iop_Sub8x8:
		case Iop_Sub16x4:
		case Iop_Sub32x2:
		case Iop_QSub8Sx8:
		case Iop_QSub16Sx4:
		case Iop_QSub32Sx2:
		case Iop_QSub64Sx1:
		case Iop_QSub8Ux8:
		case Iop_QSub16Ux4:
		case Iop_QSub32Ux2:
		case Iop_QSub64Ux1:
		case Iop_Shl8x8:
		case Iop_Shl16x4:
		case Iop_Shl32x2:
		case Iop_Shr8x8:
		case Iop_Shr16x4:
		case Iop_Shr32x2:
		case Iop_Sar8x8:
		case Iop_Sar16x4:
		case Iop_Sar32x2:
		case Iop_Sal8x8:
		case Iop_Sal16x4:
		case Iop_Sal32x2:
		case Iop_Sal64x1:
		case Iop_QShl8x8:
		case Iop_QShl16x4:
		case Iop_QShl32x2:
		case Iop_QShl64x1:
		case Iop_QSal8x8:
		case Iop_QSal16x4:
		case Iop_QSal32x2:
		case Iop_QSal64x1:
		case Iop_RecipStep32Fx2:
		case Iop_RSqrtStep32Fx2:
			return BINARY(Ity_I64, Ity_I64, Ity_I64);

		case Iop_ShlN32x2:
		case Iop_ShlN16x4:
		case Iop_ShlN8x8:
		case Iop_ShrN32x2:
		case Iop_ShrN16x4:
		case Iop_ShrN8x8:
		case Iop_SarN32x2:
		case Iop_SarN16x4:
		case Iop_SarN8x8:
		case Iop_QShlNsatUU8x8:
		case Iop_QShlNsatUU16x4:
		case Iop_QShlNsatUU32x2:
		case Iop_QShlNsatUU64x1:
		case Iop_QShlNsatSU8x8:
		case Iop_QShlNsatSU16x4:
		case Iop_QShlNsatSU32x2:
		case Iop_QShlNsatSU64x1:
		case Iop_QShlNsatSS8x8:
		case Iop_QShlNsatSS16x4:
		case Iop_QShlNsatSS32x2:
		case Iop_QShlNsatSS64x1:
			return BINARY(Ity_I64, Ity_I8, Ity_I64);

		case Iop_Shl8:
		case Iop_Shr8:
		case Iop_Sar8:
			return BINARY(Ity_I8, Ity_I8, Ity_I8);
		case Iop_Shl16:
		case Iop_Shr16:
		case Iop_Sar16:
			return BINARY(Ity_I16, Ity_I8, Ity_I16);
		case Iop_Shl32:
		case Iop_Shr32:
		case Iop_Sar32:
			return BINARY(Ity_I32, Ity_I8, Ity_I32);
		case Iop_Shl64:
		case Iop_Shr64:
		case Iop_Sar64:
			return BINARY(Ity_I64, Ity_I8, Ity_I64);

		case Iop_Not8:
			return UNARY(Ity_I8, Ity_I8);
		case Iop_Not16:
			return UNARY(Ity_I16, Ity_I16);
		case Iop_Not32:
		case Iop_CmpNEZ16x2:
		case Iop_CmpNEZ8x4:
			return UNARY(Ity_I32, Ity_I32);

		case Iop_Not64:
		case Iop_CmpNEZ32x2:
		case Iop_CmpNEZ16x4:
		case Iop_CmpNEZ8x8:
		case Iop_Cnt8x8:
		case Iop_Clz8x8:
		case Iop_Clz16x4:
		case Iop_Clz32x2:
		case Iop_Cls8x8:
		case Iop_Cls16x4:
		case Iop_Cls32x2:
		case Iop_PwAddL8Ux8:
		case Iop_PwAddL16Ux4:
		case Iop_PwAddL32Ux2:
		case Iop_PwAddL8Sx8:
		case Iop_PwAddL16Sx4:
		case Iop_PwAddL32Sx2:
		case Iop_Reverse8sIn64_x1:
		case Iop_Reverse16sIn64_x1:
		case Iop_Reverse32sIn64_x1:
		case Iop_Reverse8sIn32_x2:
		case Iop_Reverse16sIn32_x2:
		case Iop_Reverse8sIn16_x4:
		case Iop_FtoI32Sx2_RZ:
		case Iop_FtoI32Ux2_RZ:
		case Iop_I32StoFx2:
		case Iop_I32UtoFx2:
		case Iop_RecipEst32Ux2:
		case Iop_RecipEst32Fx2:
		case Iop_Abs32Fx2:
		case Iop_RSqrtEst32Fx2:
		case Iop_RSqrtEst32Ux2:
		case Iop_Neg32Fx2:
		case Iop_Abs8x8:
		case Iop_Abs16x4:
		case Iop_Abs32x2:
			return UNARY(Ity_I64, Ity_I64);

		case Iop_CmpEQ8:
		case Iop_CmpNE8:
		case Iop_CasCmpEQ8:
		case Iop_CasCmpNE8:
		case Iop_ExpCmpNE8:
			return COMPARISON(Ity_I8);
		case Iop_CmpEQ16:
		case Iop_CmpNE16:
		case Iop_CasCmpEQ16:
		case Iop_CasCmpNE16:
		case Iop_ExpCmpNE16:
			return COMPARISON(Ity_I16);
		case Iop_CmpEQ32:
		case Iop_CmpNE32:
		case Iop_CasCmpEQ32:
		case Iop_CasCmpNE32:
		case Iop_ExpCmpNE32:
		case Iop_CmpLT32S:
		case Iop_CmpLE32S:
		case Iop_CmpLT32U:
		case Iop_CmpLE32U:
			return COMPARISON(Ity_I32);
		case Iop_CmpEQ64:
		case Iop_CmpNE64:
		case Iop_CasCmpEQ64:
		case Iop_CasCmpNE64:
		case Iop_ExpCmpNE64:
		case Iop_CmpLT64S:
		case Iop_CmpLE64S:
		case Iop_CmpLT64U:
		case Iop_CmpLE64U:
			return COMPARISON(Ity_I64);

		case Iop_CmpNEZ8:
			return UNARY_COMPARISON(Ity_I8);
		case Iop_CmpNEZ16:
			return UNARY_COMPARISON(Ity_I16);
		case Iop_CmpNEZ32:
			return UNARY_COMPARISON(Ity_I32);
		case Iop_CmpNEZ64:
			return UNARY_COMPARISON(Ity_I64);

		case Iop_Left8:
			return UNARY(Ity_I8, Ity_I8);
		case Iop_Left16:
			return UNARY(Ity_I16, Ity_I16);
		case Iop_CmpwNEZ32:
		case Iop_Left32:
			return UNARY(Ity_I32, Ity_I32);
		case Iop_CmpwNEZ64:
		case Iop_Left64:
			return UNARY(Ity_I64, Ity_I64);

		case Iop_GetMSBs8x8:
			return UNARY(Ity_I64, Ity_I8);
		case Iop_GetMSBs8x16:
			return UNARY(Ity_V128, Ity_I16);

		case Iop_MullU8:
		case Iop_MullS8:
			return BINARY(Ity_I8, Ity_I8, Ity_I16);
		case Iop_MullU16:
		case Iop_MullS16:
			return BINARY(Ity_I16, Ity_I16, Ity_I32);
		case Iop_MullU32:
		case Iop_MullS32:
			return BINARY(Ity_I32, Ity_I32, Ity_I64);
		case Iop_MullU64:
		case Iop_MullS64:
			return BINARY(Ity_I64, Ity_I64, Ity_I128);

		case Iop_Clz32:
		case Iop_Ctz32:
			return UNARY(Ity_I32, Ity_I32);

		case Iop_Clz64:
		case Iop_Ctz64:
			return UNARY(Ity_I64, Ity_I64);

		case Iop_DivU32:
		case Iop_DivS32:
		case Iop_DivU32E:
		case Iop_DivS32E:
			return BINARY(Ity_I32, Ity_I32, Ity_I32);

		case Iop_DivU64:
		case Iop_DivS64:
		case Iop_DivS64E:
		case Iop_DivU64E:
			return BINARY(Ity_I64, Ity_I64, Ity_I64);

		case Iop_DivModU64to32:
		case Iop_DivModS64to32:
			return BINARY(Ity_I64, Ity_I32, Ity_I64);

		case Iop_DivModU128to64:
		case Iop_DivModS128to64:
			return BINARY(Ity_I128, Ity_I64, Ity_I128);

		case Iop_DivModS64to64:
			return BINARY(Ity_I64, Ity_I64, Ity_I128);

		case Iop_16HIto8:
		case Iop_16to8:
			return UNARY(Ity_I16, Ity_I8);
		case Iop_8HLto16:
			return BINARY(Ity_I8, Ity_I8, Ity_I16);

		case Iop_32HIto16:
		case Iop_32to16:
			return UNARY(Ity_I32, Ity_I16);
		case Iop_16HLto32:
			return BINARY(Ity_I16, Ity_I16, Ity_I32);

		case Iop_64HIto32:
		case Iop_64to32:
			return UNARY(Ity_I64, Ity_I32);
		case Iop_32HLto64:
			return BINARY(Ity_I32, Ity_I32, Ity_I64);

		case Iop_128HIto64:
		case Iop_128to64:
			return UNARY(Ity_I128, Ity_I64);
		case Iop_64HLto128:
			return BINARY(Ity_I64, Ity_I64, Ity_I128);

		case Iop_Not1:
			return UNARY(Ity_I1, Ity_I1);
		case Iop_1Uto8:
			return UNARY(Ity_I1, Ity_I8);
		case Iop_1Sto8:
			return UNARY(Ity_I1, Ity_I8);
		case Iop_1Sto16:
			return UNARY(Ity_I1, Ity_I16);
		case Iop_1Uto32:
		case Iop_1Sto32:
			return UNARY(Ity_I1, Ity_I32);
		case Iop_1Sto64:
		case Iop_1Uto64:
			return UNARY(Ity_I1, Ity_I64);
		case Iop_32to1:
			return UNARY(Ity_I32, Ity_I1);
		case Iop_64to1:
			return UNARY(Ity_I64, Ity_I1);

		case Iop_8Uto32:
		case Iop_8Sto32:
			return UNARY(Ity_I8, Ity_I32);

		case Iop_8Uto16:
		case Iop_8Sto16:
			return UNARY(Ity_I8, Ity_I16);

		case Iop_16Uto32:
		case Iop_16Sto32:
			return UNARY(Ity_I16, Ity_I32);

		case Iop_32Sto64:
		case Iop_32Uto64:
			return UNARY(Ity_I32, Ity_I64);

		case Iop_8Uto64:
		case Iop_8Sto64:
			return UNARY(Ity_I8, Ity_I64);

		case Iop_16Uto64:
		case Iop_16Sto64:
			return UNARY(Ity_I16, Ity_I64);
		case Iop_64to16:
			return UNARY(Ity_I64, Ity_I16);

		case Iop_32to8:
			return UNARY(Ity_I32, Ity_I8);
		case Iop_64to8:
			return UNARY(Ity_I64, Ity_I8);

		case Iop_AddF64:
		case Iop_SubF64:
		case Iop_MulF64:
		case Iop_DivF64:
		case Iop_AddF64r32:
		case Iop_SubF64r32:
		case Iop_MulF64r32:
		case Iop_DivF64r32:
			return TERNARY(ity_RMode, Ity_F64, Ity_F64, Ity_F64);

		case Iop_AddF32:
		case Iop_SubF32:
		case Iop_MulF32:
		case Iop_DivF32:
			return TERNARY(ity_RMode, Ity_F32, Ity_F32, Ity_F32);

		case Iop_NegF64:
		case Iop_AbsF64:
			return UNARY(Ity_F64, Ity_F64);

		case Iop_NegF32:
		case Iop_AbsF32:
			return UNARY(Ity_F32, Ity_F32);

		case Iop_SqrtF64:
		case Iop_RecpExpF64:
			return BINARY(ity_RMode, Ity_F64, Ity_F64);

		case Iop_SqrtF32:
		case Iop_RoundF32toInt:
		case Iop_RecpExpF32:
			return BINARY(ity_RMode, Ity_F32, Ity_F32);

		case Iop_CmpF32:
			return BINARY(Ity_F32, Ity_F32, Ity_I32);

		case Iop_CmpF64:
			return BINARY(Ity_F64, Ity_F64, Ity_I32);

		case Iop_CmpF128:
			return BINARY(Ity_F128, Ity_F128, Ity_I32);

		case Iop_F64toI16S:
			return BINARY(ity_RMode, Ity_F64, Ity_I16);
		case Iop_F64toI32S:
			return BINARY(ity_RMode, Ity_F64, Ity_I32);
		case Iop_F64toI64S:
		case Iop_F64toI64U:
			return BINARY(ity_RMode, Ity_F64, Ity_I64);

		case Iop_F64toI32U:
			return BINARY(ity_RMode, Ity_F64, Ity_I32);

		case Iop_I32StoF64:
			return UNARY(Ity_I32, Ity_F64);
		case Iop_I64StoF64:
			return BINARY(ity_RMode, Ity_I64, Ity_F64);
		case Iop_I64UtoF64:
			return BINARY(ity_RMode, Ity_I64, Ity_F64);
		case Iop_I64UtoF32:
			return BINARY(ity_RMode, Ity_I64, Ity_F32);

		case Iop_I32UtoF64:
			return UNARY(Ity_I32, Ity_F64);

		case Iop_F32toI32S:
			return BINARY(ity_RMode, Ity_F32, Ity_I32);
		case Iop_F32toI64S:
			return BINARY(ity_RMode, Ity_F32, Ity_I64);
		case Iop_F32toI32U:
			return BINARY(ity_RMode, Ity_F32, Ity_I32);
		case Iop_F32toI64U:
			return BINARY(ity_RMode, Ity_F32, Ity_I64);

		case Iop_I32UtoF32:
			return BINARY(ity_RMode, Ity_I32, Ity_F32);
		case Iop_I32StoF32:
			return BINARY(ity_RMode, Ity_I32, Ity_F32);
		case Iop_I64StoF32:
			return BINARY(ity_RMode, Ity_I64, Ity_F32);

		case Iop_F32toF64:
			return UNARY(Ity_F32, Ity_F64);
		case Iop_F16toF64:
			return UNARY(Ity_F16, Ity_F64);
		case Iop_F16toF32:
			return UNARY(Ity_F16, Ity_F32);

		case Iop_F64toF32:
			return BINARY(ity_RMode, Ity_F64, Ity_F32);
		case Iop_F64toF16:
			return BINARY(ity_RMode, Ity_F64, Ity_F16);
		case Iop_F32toF16:
			return BINARY(ity_RMode, Ity_F32, Ity_F16);

		case Iop_ReinterpI64asF64:
			return UNARY(Ity_I64, Ity_F64);
		case Iop_ReinterpF64asI64:
			return UNARY(Ity_F64, Ity_I64);
		case Iop_ReinterpI32asF32:
			return UNARY(Ity_I32, Ity_F32);
		case Iop_ReinterpF32asI32:
			return UNARY(Ity_F32, Ity_I32);

		case Iop_AtanF64:
		case Iop_Yl2xF64:
		case Iop_Yl2xp1F64:
		case Iop_ScaleF64:
		case Iop_PRemF64:
		case Iop_PRem1F64:
			return TERNARY(ity_RMode, Ity_F64, Ity_F64, Ity_F64);

		case Iop_PRemC3210F64:
		case Iop_PRem1C3210F64:
			return TERNARY(ity_RMode, Ity_F64, Ity_F64, Ity_I32);

		case Iop_SinF64:
		case Iop_CosF64:
		case Iop_TanF64:
		case Iop_2xm1F64:
		case Iop_RoundF64toInt:
			return BINARY(ity_RMode, Ity_F64, Ity_F64);

		case Iop_MAddF64:
		case Iop_MSubF64:
		case Iop_MAddF64r32:
		case Iop_MSubF64r32:
			return QUATERNARY(ity_RMode, Ity_F64, Ity_F64, Ity_F64, Ity_F64);

		case Iop_RSqrtEst5GoodF64:
		case Iop_RoundF64toF64_NEAREST:
		case Iop_RoundF64toF64_NegINF:
		case Iop_RoundF64toF64_PosINF:
		case Iop_RoundF64toF64_ZERO:
			return UNARY(Ity_F64, Ity_F64);
		case Iop_RoundF64toF32:
			return BINARY(ity_RMode, Ity_F64, Ity_F64);
		case Iop_TruncF64asF32:
			return UNARY(Ity_F64, Ity_F32);

		case Iop_I32UtoFx4:
		case Iop_I32StoFx4:
		case Iop_QFtoI32Ux4_RZ:
		case Iop_QFtoI32Sx4_RZ:
		case Iop_FtoI32Ux4_RZ:
		case Iop_FtoI32Sx4_RZ:
		case Iop_RoundF32x4_RM:
		case Iop_RoundF32x4_RP:
		case Iop_RoundF32x4_RN:
		case Iop_RoundF32x4_RZ:
		case Iop_Abs64Fx2:
		case Iop_Abs32Fx4:
		case Iop_RSqrtEst32Fx4:
		case Iop_RSqrtEst32Ux4:
			return UNARY(Ity_V128, Ity_V128);

		case Iop_Sqrt64Fx2:
		case Iop_Sqrt32Fx4:
			return BINARY(ity_RMode, Ity_V128, Ity_V128);

		case Iop_64HLtoV128:
			return BINARY(Ity_I64, Ity_I64, Ity_V128);

		case Iop_V128to64:
		case Iop_V128HIto64:
		case Iop_NarrowUn16to8x8:
		case Iop_NarrowUn32to16x4:
		case Iop_NarrowUn64to32x2:
		case Iop_QNarrowUn16Uto8Ux8:
		case Iop_QNarrowUn32Uto16Ux4:
		case Iop_QNarrowUn64Uto32Ux2:
		case Iop_QNarrowUn16Sto8Sx8:
		case Iop_QNarrowUn32Sto16Sx4:
		case Iop_QNarrowUn64Sto32Sx2:
		case Iop_QNarrowUn16Sto8Ux8:
		case Iop_QNarrowUn32Sto16Ux4:
		case Iop_QNarrowUn64Sto32Ux2:
		case Iop_F32toF16x4:
			return UNARY(Ity_V128, Ity_I64);

		case Iop_Widen8Uto16x8:
		case Iop_Widen16Uto32x4:
		case Iop_Widen32Uto64x2:
		case Iop_Widen8Sto16x8:
		case Iop_Widen16Sto32x4:
		case Iop_Widen32Sto64x2:
		case Iop_F16toF32x4:
			return UNARY(Ity_I64, Ity_V128);

		case Iop_V128to32:
			return UNARY(Ity_V128, Ity_I32);
		case Iop_32UtoV128:
			return UNARY(Ity_I32, Ity_V128);
		case Iop_64UtoV128:
			return UNARY(Ity_I64, Ity_V128);
		case Iop_SetV128lo32:
			return BINARY(Ity_V128, Ity_I32, Ity_V128);
		case Iop_SetV128lo64:
			return BINARY(Ity_V128, Ity_I64, Ity_V128);

		case Iop_Dup8x16:
			return UNARY(Ity_I8, Ity_V128);
		case Iop_Dup16x8:
			return UNARY(Ity_I16, Ity_V128);
		case Iop_Dup32x4:
			return UNARY(Ity_I32, Ity_V128);
		case Iop_Dup8x8:
			return UNARY(Ity_I8, Ity_I64);
		case Iop_Dup16x4:
			return UNARY(Ity_I16, Ity_I64);
		case Iop_Dup32x2:
			return UNARY(Ity_I32, Ity_I64);

		case Iop_CmpEQ32Fx4:
		case Iop_CmpLT32Fx4:
		case Iop_CmpEQ64Fx2:
		case Iop_CmpLT64Fx2:
		case Iop_CmpLE32Fx4:
		case Iop_CmpUN32Fx4:
		case Iop_CmpLE64Fx2:
		case Iop_CmpUN64Fx2:
		case Iop_CmpGT32Fx4:
		case Iop_CmpGE32Fx4:
		case Iop_CmpEQ32F0x4:
		case Iop_CmpLT32F0x4:
		case Iop_CmpEQ64F0x2:
		case Iop_CmpLT64F0x2:
		case Iop_CmpLE32F0x4:
		case Iop_CmpUN32F0x4:
		case Iop_CmpLE64F0x2:
		case Iop_CmpUN64F0x2:
		case Iop_Add32F0x4:
		case Iop_Add64F0x2:
		case Iop_Div32F0x4:
		case Iop_Div64F0x2:
		case Iop_Max32Fx4:
		case Iop_Max32F0x4:
		case Iop_PwMax32Fx4:
		case Iop_PwMin32Fx4:
		case Iop_Max64Fx2:
		case Iop_Max64F0x2:
		case Iop_Min32Fx4:
		case Iop_Min32F0x4:
		case Iop_Min64Fx2:
		case Iop_Min64F0x2:
		case Iop_Mul32F0x4:
		case Iop_Mul64F0x2:
		case Iop_Sub32F0x4:
		case Iop_Sub64F0x2:
		case Iop_AndV128:
		case Iop_OrV128:
		case Iop_XorV128:
		case Iop_Add8x16:
		case Iop_Add16x8:
		case Iop_Add32x4:
		case Iop_Add64x2:
		case Iop_QAdd8Ux16:
		case Iop_QAdd16Ux8:
		case Iop_QAdd32Ux4:
		case Iop_QAdd64Ux2:
		case Iop_QAdd8Sx16:
		case Iop_QAdd16Sx8:
		case Iop_QAdd32Sx4:
		case Iop_QAdd64Sx2:
		case Iop_QAddExtUSsatSS8x16:
		case Iop_QAddExtUSsatSS16x8:
		case Iop_QAddExtUSsatSS32x4:
		case Iop_QAddExtUSsatSS64x2:
		case Iop_QAddExtSUsatUU8x16:
		case Iop_QAddExtSUsatUU16x8:
		case Iop_QAddExtSUsatUU32x4:
		case Iop_QAddExtSUsatUU64x2:
		case Iop_PwAdd8x16:
		case Iop_PwAdd16x8:
		case Iop_PwAdd32x4:
		case Iop_Sub8x16:
		case Iop_Sub16x8:
		case Iop_Sub32x4:
		case Iop_Sub64x2:
		case Iop_QSub8Ux16:
		case Iop_QSub16Ux8:
		case Iop_QSub32Ux4:
		case Iop_QSub64Ux2:
		case Iop_QSub8Sx16:
		case Iop_QSub16Sx8:
		case Iop_QSub32Sx4:
		case Iop_QSub64Sx2:
		case Iop_Mul8x16:
		case Iop_Mul16x8:
		case Iop_Mul32x4:
		case Iop_PolynomialMul8x16:
		case Iop_PolynomialMulAdd8x16:
		case Iop_PolynomialMulAdd16x8:
		case Iop_PolynomialMulAdd32x4:
		case Iop_PolynomialMulAdd64x2:
		case Iop_MulHi16Ux8:
		case Iop_MulHi32Ux4:
		case Iop_MulHi16Sx8:
		case Iop_MulHi32Sx4:
		case Iop_QDMulHi16Sx8:
		case Iop_QDMulHi32Sx4:
		case Iop_QRDMulHi16Sx8:
		case Iop_QRDMulHi32Sx4:
		case Iop_MullEven8Ux16:
		case Iop_MullEven16Ux8:
		case Iop_MullEven32Ux4:
		case Iop_MullEven8Sx16:
		case Iop_MullEven16Sx8:
		case Iop_MullEven32Sx4:
		case Iop_Avg8Ux16:
		case Iop_Avg16Ux8:
		case Iop_Avg32Ux4:
		case Iop_Avg8Sx16:
		case Iop_Avg16Sx8:
		case Iop_Avg32Sx4:
		case Iop_Max8Sx16:
		case Iop_Max16Sx8:
		case Iop_Max32Sx4:
		case Iop_Max64Sx2:
		case Iop_Max8Ux16:
		case Iop_Max16Ux8:
		case Iop_Max32Ux4:
		case Iop_Max64Ux2:
		case Iop_Min8Sx16:
		case Iop_Min16Sx8:
		case Iop_Min32Sx4:
		case Iop_Min64Sx2:
		case Iop_Min8Ux16:
		case Iop_Min16Ux8:
		case Iop_Min32Ux4:
		case Iop_Min64Ux2:
		case Iop_CmpEQ8x16:
		case Iop_CmpEQ16x8:
		case Iop_CmpEQ32x4:
		case Iop_CmpEQ64x2:
		case Iop_CmpGT8Sx16:
		case Iop_CmpGT16Sx8:
		case Iop_CmpGT32Sx4:
		case Iop_CmpGT64Sx2:
		case Iop_CmpGT8Ux16:
		case Iop_CmpGT16Ux8:
		case Iop_CmpGT32Ux4:
		case Iop_CmpGT64Ux2:
		case Iop_Shl8x16:
		case Iop_Shl16x8:
		case Iop_Shl32x4:
		case Iop_Shl64x2:
		case Iop_QShl8x16:
		case Iop_QShl16x8:
		case Iop_QShl32x4:
		case Iop_QShl64x2:
		case Iop_QSal8x16:
		case Iop_QSal16x8:
		case Iop_QSal32x4:
		case Iop_QSal64x2:
		case Iop_Shr8x16:
		case Iop_Shr16x8:
		case Iop_Shr32x4:
		case Iop_Shr64x2:
		case Iop_Sar8x16:
		case Iop_Sar16x8:
		case Iop_Sar32x4:
		case Iop_Sar64x2:
		case Iop_Sal8x16:
		case Iop_Sal16x8:
		case Iop_Sal32x4:
		case Iop_Sal64x2:
		case Iop_Rol8x16:
		case Iop_Rol16x8:
		case Iop_Rol32x4:
		case Iop_Rol64x2:
		case Iop_QNarrowBin16Sto8Ux16:
		case Iop_QNarrowBin32Sto16Ux8:
		case Iop_QNarrowBin16Sto8Sx16:
		case Iop_QNarrowBin32Sto16Sx8:
		case Iop_QNarrowBin16Uto8Ux16:
		case Iop_QNarrowBin32Uto16Ux8:
		case Iop_QNarrowBin64Sto32Sx4:
		case Iop_QNarrowBin64Uto32Ux4:
		case Iop_NarrowBin16to8x16:
		case Iop_NarrowBin32to16x8:
		case Iop_NarrowBin64to32x4:
		case Iop_InterleaveHI8x16:
		case Iop_InterleaveHI16x8:
		case Iop_InterleaveHI32x4:
		case Iop_InterleaveHI64x2:
		case Iop_InterleaveLO8x16:
		case Iop_InterleaveLO16x8:
		case Iop_InterleaveLO32x4:
		case Iop_InterleaveLO64x2:
		case Iop_CatOddLanes8x16:
		case Iop_CatEvenLanes8x16:
		case Iop_CatOddLanes16x8:
		case Iop_CatEvenLanes16x8:
		case Iop_CatOddLanes32x4:
		case Iop_CatEvenLanes32x4:
		case Iop_InterleaveOddLanes8x16:
		case Iop_InterleaveEvenLanes8x16:
		case Iop_InterleaveOddLanes16x8:
		case Iop_InterleaveEvenLanes16x8:
		case Iop_InterleaveOddLanes32x4:
		case Iop_InterleaveEvenLanes32x4:
		case Iop_Perm8x16:
		case Iop_Perm32x4:
		case Iop_RecipStep32Fx4:
		case Iop_RecipStep64Fx2:
		case Iop_RSqrtStep32Fx4:
		case Iop_RSqrtStep64Fx2:
		case Iop_CipherV128:
		case Iop_CipherLV128:
		case Iop_NCipherV128:
		case Iop_NCipherLV128:
		case Iop_Sh8Sx16:
		case Iop_Sh16Sx8:
		case Iop_Sh32Sx4:
		case Iop_Sh64Sx2:
		case Iop_Sh8Ux16:
		case Iop_Sh16Ux8:
		case Iop_Sh32Ux4:
		case Iop_Sh64Ux2:
		case Iop_Rsh8Sx16:
		case Iop_Rsh16Sx8:
		case Iop_Rsh32Sx4:
		case Iop_Rsh64Sx2:
		case Iop_Rsh8Ux16:
		case Iop_Rsh16Ux8:
		case Iop_Rsh32Ux4:
		case Iop_Rsh64Ux2:
			return BINARY(Ity_V128, Ity_V128, Ity_V128);

		case Iop_PolynomialMull8x8:
		case Iop_Mull8Ux8:
		case Iop_Mull8Sx8:
		case Iop_Mull16Ux4:
		case Iop_Mull16Sx4:
		case Iop_Mull32Ux2:
		case Iop_Mull32Sx2:
			return BINARY(Ity_I64, Ity_I64, Ity_V128);

		case Iop_NotV128:
		case Iop_RecipEst32Fx4:
		case Iop_RecipEst32F0x4:
		case Iop_RecipEst64Fx2:
		case Iop_RSqrtEst64Fx2:
		case Iop_RecipEst32Ux4:
		case Iop_RSqrtEst32F0x4:
		case Iop_Sqrt32F0x4:
		case Iop_Sqrt64F0x2:
		case Iop_CmpNEZ8x16:
		case Iop_CmpNEZ16x8:
		case Iop_CmpNEZ32x4:
		case Iop_CmpNEZ64x2:
		case Iop_Cnt8x16:
		case Iop_Clz8x16:
		case Iop_Clz16x8:
		case Iop_Clz32x4:
		case Iop_Clz64x2:
		case Iop_Cls8x16:
		case Iop_Cls16x8:
		case Iop_Cls32x4:
		case Iop_PwAddL8Ux16:
		case Iop_PwAddL16Ux8:
		case Iop_PwAddL32Ux4:
		case Iop_PwAddL8Sx16:
		case Iop_PwAddL16Sx8:
		case Iop_PwAddL32Sx4:
		case Iop_Reverse8sIn64_x2:
		case Iop_Reverse16sIn64_x2:
		case Iop_Reverse32sIn64_x2:
		case Iop_Reverse8sIn32_x4:
		case Iop_Reverse16sIn32_x4:
		case Iop_Reverse8sIn16_x8:
		case Iop_Reverse1sIn8_x16:
		case Iop_Neg64Fx2:
		case Iop_Neg32Fx4:
		case Iop_Abs8x16:
		case Iop_Abs16x8:
		case Iop_Abs32x4:
		case Iop_Abs64x2:
		case Iop_CipherSV128:
		case Iop_PwBitMtxXpose64x2:
		case Iop_ZeroHI64ofV128:
		case Iop_ZeroHI96ofV128:
		case Iop_ZeroHI112ofV128:
		case Iop_ZeroHI120ofV128:
			return UNARY(Ity_V128, Ity_V128);

		case Iop_ShlV128:
		case Iop_ShrV128:
		case Iop_ShlN8x16:
		case Iop_ShlN16x8:
		case Iop_ShlN32x4:
		case Iop_ShlN64x2:
		case Iop_ShrN8x16:
		case Iop_ShrN16x8:
		case Iop_ShrN32x4:
		case Iop_ShrN64x2:
		case Iop_SarN8x16:
		case Iop_SarN16x8:
		case Iop_SarN32x4:
		case Iop_SarN64x2:
		case Iop_QShlNsatUU8x16:
		case Iop_QShlNsatUU16x8:
		case Iop_QShlNsatUU32x4:
		case Iop_QShlNsatUU64x2:
		case Iop_QShlNsatSU8x16:
		case Iop_QShlNsatSU16x8:
		case Iop_QShlNsatSU32x4:
		case Iop_QShlNsatSU64x2:
		case Iop_QShlNsatSS8x16:
		case Iop_QShlNsatSS16x8:
		case Iop_QShlNsatSS32x4:
		case Iop_QShlNsatSS64x2:
		case Iop_SHA256:
		case Iop_SHA512:
		case Iop_QandQShrNnarrow16Uto8Ux8:
		case Iop_QandQShrNnarrow32Uto16Ux4:
		case Iop_QandQShrNnarrow64Uto32Ux2:
		case Iop_QandQSarNnarrow16Sto8Sx8:
		case Iop_QandQSarNnarrow32Sto16Sx4:
		case Iop_QandQSarNnarrow64Sto32Sx2:
		case Iop_QandQSarNnarrow16Sto8Ux8:
		case Iop_QandQSarNnarrow32Sto16Ux4:
		case Iop_QandQSarNnarrow64Sto32Ux2:
		case Iop_QandQRShrNnarrow16Uto8Ux8:
		case Iop_QandQRShrNnarrow32Uto16Ux4:
		case Iop_QandQRShrNnarrow64Uto32Ux2:
		case Iop_QandQRSarNnarrow16Sto8Sx8:
		case Iop_QandQRSarNnarrow32Sto16Sx4:
		case Iop_QandQRSarNnarrow64Sto32Sx2:
		case Iop_QandQRSarNnarrow16Sto8Ux8:
		case Iop_QandQRSarNnarrow32Sto16Ux4:
		case Iop_QandQRSarNnarrow64Sto32Ux2:
			return BINARY(Ity_V128, Ity_I8, Ity_V128);

		case Iop_F32ToFixed32Ux4_RZ:
		case Iop_F32ToFixed32Sx4_RZ:
		case Iop_Fixed32UToF32x4_RN:
		case Iop_Fixed32SToF32x4_RN:
			return BINARY(Ity_V128, Ity_I8, Ity_V128);

		case Iop_F32ToFixed32Ux2_RZ:
		case Iop_F32ToFixed32Sx2_RZ:
		case Iop_Fixed32UToF32x2_RN:
		case Iop_Fixed32SToF32x2_RN:
			return BINARY(Ity_I64, Ity_I8, Ity_I64);

		case Iop_GetElem8x16:
			return BINARY(Ity_V128, Ity_I8, Ity_I8);
		case Iop_GetElem16x8:
			return BINARY(Ity_V128, Ity_I8, Ity_I16);
		case Iop_GetElem32x4:
			return BINARY(Ity_V128, Ity_I8, Ity_I32);
		case Iop_GetElem64x2:
			return BINARY(Ity_V128, Ity_I8, Ity_I64);
		case Iop_GetElem8x8:
			return BINARY(Ity_I64, Ity_I8, Ity_I8);
		case Iop_GetElem16x4:
			return BINARY(Ity_I64, Ity_I8, Ity_I16);
		case Iop_GetElem32x2:
			return BINARY(Ity_I64, Ity_I8, Ity_I32);
		case Iop_SetElem8x8:
			return TERNARY(Ity_I64, Ity_I8, Ity_I8, Ity_I64);
		case Iop_SetElem16x4:
			return TERNARY(Ity_I64, Ity_I8, Ity_I16, Ity_I64);
		case Iop_SetElem32x2:
			return TERNARY(Ity_I64, Ity_I8, Ity_I32, Ity_I64);

		case Iop_Slice64:
			return TERNARY(Ity_I64, Ity_I64, Ity_I8, Ity_I64);
		case Iop_SliceV128:
			return TERNARY(Ity_V128, Ity_V128, Ity_I8, Ity_V128);

		case Iop_BCDAdd:
		case Iop_BCDSub:
			return TERNARY(Ity_V128, Ity_V128, Ity_I8, Ity_V128);
		case Iop_QDMull16Sx4:
		case Iop_QDMull32Sx2:
			return BINARY(Ity_I64, Ity_I64, Ity_V128);

		/* s390 specific */
		case Iop_MAddF32:
		case Iop_MSubF32:
			return QUATERNARY(ity_RMode, Ity_F32, Ity_F32, Ity_F32, Ity_F32);

		case Iop_F64HLtoF128:
			return BINARY(Ity_F64, Ity_F64, Ity_F128);

		case Iop_F128HItoF64:
		case Iop_F128LOtoF64:
			return UNARY(Ity_F128, Ity_F64);

		case Iop_AddF128:
		case Iop_SubF128:
		case Iop_MulF128:
		case Iop_DivF128:
			return TERNARY(ity_RMode, Ity_F128, Ity_F128, Ity_F128);

		case Iop_Add64Fx2:
		case Iop_Sub64Fx2:
		case Iop_Mul64Fx2:
		case Iop_Div64Fx2:
		case Iop_Add32Fx4:
		case Iop_Sub32Fx4:
		case Iop_Mul32Fx4:
		case Iop_Div32Fx4:
			return TERNARY(ity_RMode, Ity_V128, Ity_V128, Ity_V128);

		case Iop_Add64Fx4:
		case Iop_Sub64Fx4:
		case Iop_Mul64Fx4:
		case Iop_Div64Fx4:
		case Iop_Add32Fx8:
		case Iop_Sub32Fx8:
		case Iop_Mul32Fx8:
		case Iop_Div32Fx8:
			return TERNARY(ity_RMode, Ity_V256, Ity_V256, Ity_V256);

		case Iop_NegF128:
		case Iop_AbsF128:
			return UNARY(Ity_F128, Ity_F128);

		case Iop_SqrtF128:
			return BINARY(ity_RMode, Ity_F128, Ity_F128);

		case Iop_I32StoF128:
			return UNARY(Ity_I32, Ity_F128);
		case Iop_I64StoF128:
			return UNARY(Ity_I64, Ity_F128);

		case Iop_I32UtoF128:
			return UNARY(Ity_I32, Ity_F128);
		case Iop_I64UtoF128:
			return UNARY(Ity_I64, Ity_F128);

		case Iop_F128toI32S:
			return BINARY(ity_RMode, Ity_F128, Ity_I32);
		case Iop_F128toI64S:
			return BINARY(ity_RMode, Ity_F128, Ity_I64);

		case Iop_F128toI32U:
			return BINARY(ity_RMode, Ity_F128, Ity_I32);
		case Iop_F128toI64U:
			return BINARY(ity_RMode, Ity_F128, Ity_I64);

		case Iop_F32toF128:
			return UNARY(Ity_F32, Ity_F128);
		case Iop_F64toF128:
			return UNARY(Ity_F64, Ity_F128);

		case Iop_F128toF32:
			return BINARY(ity_RMode, Ity_F128, Ity_F32);
		case Iop_F128toF64:
			return BINARY(ity_RMode, Ity_F128, Ity_F64);

		case Iop_D32toD64:
			return UNARY(Ity_D32, Ity_D64);

		case Iop_ExtractExpD64:
			return UNARY(Ity_D64, Ity_I64);

		case Iop_ExtractSigD64:
			return UNARY(Ity_D64, Ity_I64);

		case Iop_InsertExpD64:
			return BINARY(Ity_I64, Ity_D64, Ity_D64);

		case Iop_ExtractExpD128:
			return UNARY(Ity_D128, Ity_I64);

		case Iop_ExtractSigD128:
			return UNARY(Ity_D128, Ity_I64);

		case Iop_InsertExpD128:
			return BINARY(Ity_I64, Ity_D128, Ity_D128);

		case Iop_D64toD128:
			return UNARY(Ity_D64, Ity_D128);

		case Iop_ReinterpD64asI64:
			return UNARY(Ity_D64, Ity_I64);

		case Iop_ReinterpI64asD64:
			return UNARY(Ity_I64, Ity_D64);

		case Iop_RoundD64toInt:
			return BINARY(ity_RMode, Ity_D64, Ity_D64);

		case Iop_RoundD128toInt:
			return BINARY(ity_RMode, Ity_D128, Ity_D128);

		case Iop_I32StoD128:
		case Iop_I32UtoD128:
			return UNARY(Ity_I32, Ity_D128);

		case Iop_I64StoD128:
			return UNARY(Ity_I64, Ity_D128);

		case Iop_I64UtoD128:
			return UNARY(Ity_I64, Ity_D128);

		case Iop_DPBtoBCD:
		case Iop_BCDtoDPB:
			return UNARY(Ity_I64, Ity_I64);

		case Iop_D128HItoD64:
		case Iop_D128LOtoD64:
			return UNARY(Ity_D128, Ity_D64);

		case Iop_D128toI64S:
			return BINARY(ity_RMode, Ity_D128, Ity_I64);

		case Iop_D128toI64U:
			return BINARY(ity_RMode, Ity_D128, Ity_I64);

		case Iop_D128toI32S:
		case Iop_D128toI32U:
			return BINARY(ity_RMode, Ity_D128, Ity_I32);

		case Iop_D64HLtoD128:
			return BINARY(Ity_D64, Ity_D64, Ity_D128);

		case Iop_ShlD64:
		case Iop_ShrD64:
			return BINARY(Ity_D64, Ity_I8, Ity_D64);

		case Iop_D64toD32:
			return BINARY(ity_RMode, Ity_D64, Ity_D32);

		case Iop_D64toI32S:
		case Iop_D64toI32U:
			return BINARY(ity_RMode, Ity_D64, Ity_I32);

		case Iop_D64toI64S:
			return BINARY(ity_RMode, Ity_D64, Ity_I64);

		case Iop_D64toI64U:
			return BINARY(ity_RMode, Ity_D64, Ity_I64);

		case Iop_I32StoD64:
		case Iop_I32UtoD64:
			return UNARY(Ity_I32, Ity_D64);

		case Iop_I64StoD64:
			return BINARY(ity_RMode, Ity_I64, Ity_D64);

		case Iop_I64UtoD64:
			return BINARY(ity_RMode, Ity_I64, Ity_D64);

		case Iop_F32toD32:
			return BINARY(ity_RMode, Ity_F32, Ity_D32);

		case Iop_F32toD64:
			return BINARY(ity_RMode, Ity_F32, Ity_D64);

		case Iop_F32toD128:
			return BINARY(ity_RMode, Ity_F32, Ity_D128);

		case Iop_F64toD32:
			return BINARY(ity_RMode, Ity_F64, Ity_D32);

		case Iop_F64toD64:
			return BINARY(ity_RMode, Ity_F64, Ity_D64);

		case Iop_F64toD128:
			return BINARY(ity_RMode, Ity_F64, Ity_D128);

		case Iop_F128toD32:
			return BINARY(ity_RMode, Ity_F128, Ity_D32);

		case Iop_F128toD64:
			return BINARY(ity_RMode, Ity_F128, Ity_D64);

		case Iop_F128toD128:
			return BINARY(ity_RMode, Ity_F128, Ity_D128);

		case Iop_D32toF32:
			return BINARY(ity_RMode, Ity_D32, Ity_F32);

		case Iop_D32toF64:
			return BINARY(ity_RMode, Ity_D32, Ity_F64);

		case Iop_D32toF128:
			return BINARY(ity_RMode, Ity_D32, Ity_F128);

		case Iop_D64toF32:
			return BINARY(ity_RMode, Ity_D64, Ity_F32);

		case Iop_D64toF64:
			return BINARY(ity_RMode, Ity_D64, Ity_F64);

		case Iop_D64toF128:
			return BINARY(ity_RMode, Ity_D64, Ity_F128);

		case Iop_D128toF32:
			return BINARY(ity_RMode, Ity_D128, Ity_F32);

		case Iop_D128toF64:
			return BINARY(ity_RMode, Ity_D128, Ity_F64);

		case Iop_D128toF128:
			return BINARY(ity_RMode, Ity_D128, Ity_F128);

		case Iop_CmpD64:
		case Iop_CmpExpD64:
			return BINARY(Ity_D64, Ity_D64, Ity_I32);

		case Iop_CmpD128:
		case Iop_CmpExpD128:
			return BINARY(Ity_D128, Ity_D128, Ity_I32);

		case Iop_QuantizeD64:
			return TERNARY(ity_RMode, Ity_D64, Ity_D64, Ity_D64);

		case Iop_SignificanceRoundD64:
			return TERNARY(ity_RMode, Ity_I8, Ity_D64, Ity_D64);

		case Iop_QuantizeD128:
			return TERNARY(ity_RMode, Ity_D128, Ity_D128, Ity_D128);

		case Iop_SignificanceRoundD128:
			return TERNARY(ity_RMode, Ity_I8, Ity_D128, Ity_D128);

		case Iop_ShlD128:
		case Iop_ShrD128:
			return BINARY(Ity_D128, Ity_I8, Ity_D128);

		case Iop_AddD64:
		case Iop_SubD64:
		case Iop_MulD64:
		case Iop_DivD64:
			return TERNARY(ity_RMode, Ity_D64, Ity_D64, Ity_D64);

		case Iop_D128toD64:
			return BINARY(ity_RMode, Ity_D128, Ity_D64);

		case Iop_AddD128:
		case Iop_SubD128:
		case Iop_MulD128:
		case Iop_DivD128:
			return TERNARY(ity_RMode, Ity_D128, Ity_D128, Ity_D128);

		case Iop_V256to64_0:
		case Iop_V256to64_1:
		case Iop_V256to64_2:
		case Iop_V256to64_3:
			return UNARY(Ity_V256, Ity_I64);

		case Iop_64x4toV256:
			return QUATERNARY(Ity_I64, Ity_I64, Ity_I64, Ity_I64, Ity_V256);

		case Iop_AndV256:
		case Iop_OrV256:
		case Iop_XorV256:
		case Iop_Max32Fx8:
		case Iop_Min32Fx8:
		case Iop_Max64Fx4:
		case Iop_Min64Fx4:
		case Iop_Add8x32:
		case Iop_Add16x16:
		case Iop_Add32x8:
		case Iop_Add64x4:
		case Iop_Sub8x32:
		case Iop_Sub16x16:
		case Iop_Sub32x8:
		case Iop_Sub64x4:
		case Iop_Mul16x16:
		case Iop_Mul32x8:
		case Iop_MulHi16Ux16:
		case Iop_MulHi16Sx16:
		case Iop_Avg8Ux32:
		case Iop_Avg16Ux16:
		case Iop_Max8Sx32:
		case Iop_Max16Sx16:
		case Iop_Max32Sx8:
		case Iop_Max8Ux32:
		case Iop_Max16Ux16:
		case Iop_Max32Ux8:
		case Iop_Min8Sx32:
		case Iop_Min16Sx16:
		case Iop_Min32Sx8:
		case Iop_Min8Ux32:
		case Iop_Min16Ux16:
		case Iop_Min32Ux8:
		case Iop_CmpEQ8x32:
		case Iop_CmpEQ16x16:
		case Iop_CmpEQ32x8:
		case Iop_CmpEQ64x4:
		case Iop_CmpGT8Sx32:
		case Iop_CmpGT16Sx16:
		case Iop_CmpGT32Sx8:
		case Iop_CmpGT64Sx4:
		case Iop_QAdd8Ux32:
		case Iop_QAdd16Ux16:
		case Iop_QAdd8Sx32:
		case Iop_QAdd16Sx16:
		case Iop_QSub8Ux32:
		case Iop_QSub16Ux16:
		case Iop_QSub8Sx32:
		case Iop_QSub16Sx16:
		case Iop_Perm32x8:
			return BINARY(Ity_V256, Ity_V256, Ity_V256);

		case Iop_V256toV128_1:
		case Iop_V256toV128_0:
			return UNARY(Ity_V256, Ity_V128);

		case Iop_QandUQsh8x16:
		case Iop_QandUQsh16x8:
		case Iop_QandUQsh32x4:
		case Iop_QandUQsh64x2:
		case Iop_QandSQsh8x16:
		case Iop_QandSQsh16x8:
		case Iop_QandSQsh32x4:
		case Iop_QandSQsh64x2:
		case Iop_QandUQRsh8x16:
		case Iop_QandUQRsh16x8:
		case Iop_QandUQRsh32x4:
		case Iop_QandUQRsh64x2:
		case Iop_QandSQRsh8x16:
		case Iop_QandSQRsh16x8:
		case Iop_QandSQRsh32x4:
		case Iop_QandSQRsh64x2:
		case Iop_V128HLtoV256:
			return BINARY(Ity_V128, Ity_V128, Ity_V256);

		case Iop_NotV256:
		case Iop_RSqrtEst32Fx8:
		case Iop_Sqrt32Fx8:
		case Iop_Sqrt64Fx4:
		case Iop_RecipEst32Fx8:
		case Iop_CmpNEZ8x32:
		case Iop_CmpNEZ16x16:
		case Iop_CmpNEZ64x4:
		case Iop_CmpNEZ32x8:
			return UNARY(Ity_V256, Ity_V256);

		case Iop_ShlN16x16:
		case Iop_ShlN32x8:
		case Iop_ShlN64x4:
		case Iop_ShrN16x16:
		case Iop_ShrN32x8:
		case Iop_ShrN64x4:
		case Iop_SarN16x16:
		case Iop_SarN32x8:
			return BINARY(Ity_V256, Ity_I8, Ity_V256);

		default:
			logger.error("Unknown type for: {}", op);
			return null;
		}
	}

	private static TypeInformation QUATERNARY(VexVariableType arg0, VexVariableType arg1, VexVariableType arg2,
			VexVariableType arg3, VexVariableType dst) {
		if (arg0 != null) {
			TypeInformation type = new TypeInformation();
			type.argType.addAll(Arrays.asList(arg0, arg1, arg2, arg3));
			type.outputType = dst;
			return type.fixRM();
		} else {
			TypeInformation type = new TypeInformation();
			type.argType.addAll(Arrays.asList(arg1, arg2, arg3));
			type.outputType = dst;
			return type.fixRM();
		}
	}

	private static TypeInformation UNARY_COMPARISON(VexVariableType arg0) {
		TypeInformation type = new TypeInformation();
		type.argType.add(arg0);
		type.outputType = VexVariableType.Ity_I1;
		return type.fixRM();
	}

	private static TypeInformation TERNARY(VexVariableType arg0, VexVariableType arg1, VexVariableType arg2,
			VexVariableType dst) {
		if (arg0 != null) {
			TypeInformation type = new TypeInformation();
			type.argType.addAll(Arrays.asList(arg0, arg1, arg2));
			type.outputType = dst;
			return type.fixRM();
		} else {
			TypeInformation type = new TypeInformation();
			type.argType.addAll(Arrays.asList(arg1, arg2));
			type.outputType = dst;
			return type.fixRM();
		}
	}

	private static TypeInformation COMPARISON(VexVariableType arg0) {
		TypeInformation type = new TypeInformation();
		type.argType.addAll(Arrays.asList(arg0, arg0));
		type.outputType = VexVariableType.Ity_I1;
		return type.fixRM();
	}

	private static TypeInformation UNARY(VexVariableType arg0, VexVariableType dst) {
		TypeInformation type = new TypeInformation();
		type.argType.addAll(Arrays.asList(arg0));
		type.outputType = dst;
		return type.fixRM();
	}

	private static TypeInformation BINARY(VexVariableType arg0, VexVariableType arg1, VexVariableType dst) {
		if (arg0 != null) {
			TypeInformation type = new TypeInformation();
			type.argType.addAll(Arrays.asList(arg0, arg1));
			type.outputType = dst;
			return type.fixRM();
		} else {
			TypeInformation type = new TypeInformation();
			type.argType.addAll(Arrays.asList(arg1));
			type.outputType = dst;
			return type.fixRM();
		}
	}

}
