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
package ca.mcgill.sis.dmas.kam1n0.vex.enumeration;

import java.util.Arrays;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;

import ca.mcgill.sis.dmas.env.StringResources;
import ca.mcgill.sis.dmas.kam1n0.vex.VexEnumeration;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.Attribute;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

public enum VexOperationType {
	/*
	 * -- Do not change this ordering. The IR generators rely on (eg) Iop_Add64
	 * == IopAdd8 + 3. --
	 */

	Iop_INVALID, Iop_Add8, Iop_Add16, Iop_Add32, Iop_Add64, Iop_Sub8, Iop_Sub16, Iop_Sub32, Iop_Sub64,
	/* Signless mul. MullS/MullU is elsewhere. */
	Iop_Mul8, Iop_Mul16, Iop_Mul32, Iop_Mul64, Iop_Or8, Iop_Or16, Iop_Or32, Iop_Or64, Iop_And8, Iop_And16, Iop_And32, Iop_And64, Iop_Xor8, Iop_Xor16, Iop_Xor32, Iop_Xor64, Iop_Shl8, Iop_Shl16, Iop_Shl32, Iop_Shl64, Iop_Shr8, Iop_Shr16, Iop_Shr32, Iop_Shr64, Iop_Sar8, Iop_Sar16, Iop_Sar32, Iop_Sar64,
	/* Integer comparisons. */
	Iop_CmpEQ8, Iop_CmpEQ16, Iop_CmpEQ32, Iop_CmpEQ64, Iop_CmpNE8, Iop_CmpNE16, Iop_CmpNE32, Iop_CmpNE64,
	/* Tags for unary ops */
	Iop_Not8, Iop_Not16, Iop_Not32, Iop_Not64,

	/*
	 * Exactly like CmpEQ8/16/32/64, but carrying the additional hint that these
	 * compute the success/failure of a CAS operation, and hence are almost
	 * certainly applied to two copies of the same value, which in turn has
	 * implications for Memcheck's instrumentation.
	 */
	Iop_CasCmpEQ8, Iop_CasCmpEQ16, Iop_CasCmpEQ32, Iop_CasCmpEQ64, Iop_CasCmpNE8, Iop_CasCmpNE16, Iop_CasCmpNE32, Iop_CasCmpNE64,

	/*
	 * Exactly like CmpNE8/16/32/64, but carrying the additional hint that these
	 * needs expensive definedness tracking.
	 */
	Iop_ExpCmpNE8, Iop_ExpCmpNE16, Iop_ExpCmpNE32, Iop_ExpCmpNE64,

	/* -- Ordering not important after here. -- */

	/* Widening multiplies */
	Iop_MullS8, Iop_MullS16, Iop_MullS32, Iop_MullS64, Iop_MullU8, Iop_MullU16, Iop_MullU32, Iop_MullU64,

	/* Wierdo integer stuff */
	Iop_Clz64, Iop_Clz32, /* count leading zeroes */
	Iop_Ctz64, Iop_Ctz32, /* count trailing zeros */
	/*
	 * Ctz64/Ctz32/Clz64/Clz32 are UNDEFINED when given arguments of zero. You
	 * must ensure they are never given a zero argument.
	 */

	/* Standard integer comparisons */
	Iop_CmpLT32S, Iop_CmpLT64S, Iop_CmpLE32S, Iop_CmpLE64S, Iop_CmpLT32U, Iop_CmpLT64U, Iop_CmpLE32U, Iop_CmpLE64U,

	/* As a sop to Valgrind-Memcheck, the following are useful. */
	Iop_CmpNEZ8, Iop_CmpNEZ16, Iop_CmpNEZ32, Iop_CmpNEZ64, Iop_CmpwNEZ32, Iop_CmpwNEZ64, /*
																							 * all-
																							 * 0s
																							 * ->
																							 * all
																							 * -
																							 * Os;
																							 * other
																							 * ->
																							 * all
																							 * -
																							 * 1s
																							 */
	Iop_Left8, Iop_Left16, Iop_Left32, Iop_Left64, /* \x -> x | -x */
	Iop_Max32U, /* unsigned max */

	/*
	 * PowerPC-style 3-way integer comparisons. Without them it is difficult to
	 * simulate PPC efficiently. op(x,y) | x < y = 0x8 else | x > y = 0x4 else |
	 * x == y = 0x2
	 */
	Iop_CmpORD32U, Iop_CmpORD64U, Iop_CmpORD32S, Iop_CmpORD64S,

	/* Division */
	/* TODO: clarify semantics wrt rounding, negative values, whatever */
	Iop_DivU32, // :: I32,I32 -> I32 (simple div, no mod)
	Iop_DivS32, // ditto, signed
	Iop_DivU64, // :: I64,I64 -> I64 (simple div, no mod)
	Iop_DivS64, // ditto, signed
	Iop_DivU64E, // :: I64,I64 -> I64 (dividend is 64-bit arg (hi)
					// concat with 64 0's (low))
	Iop_DivS64E, // ditto, signed
	Iop_DivU32E, // :: I32,I32 -> I32 (dividend is 32-bit arg (hi)
					// concat with 32 0's (low))
	Iop_DivS32E, // ditto, signed

	Iop_DivModU64to32, // :: I64,I32 -> I64
						// of which lo half is div and hi half is mod
	Iop_DivModS64to32, // ditto, signed

	Iop_DivModU128to64, // :: V128,I64 -> V128
						// of which lo half is div and hi half is mod
	Iop_DivModS128to64, // ditto, signed

	Iop_DivModS64to64, // :: I64,I64 -> I128
						// of which lo half is div and hi half is mod

	/*
	 * Integer conversions. Some of these are redundant (eg Iop_64to8 is the
	 * same as Iop_64to32 and then Iop_32to8), but having a complete set reduces
	 * the typical dynamic size of IR and makes the instruction selectors easier
	 * to write.
	 */

	/* Widening conversions */
	Iop_8Uto16, Iop_8Uto32, Iop_8Uto64, Iop_16Uto32, Iop_16Uto64, Iop_32Uto64, Iop_8Sto16, Iop_8Sto32, Iop_8Sto64, Iop_16Sto32, Iop_16Sto64, Iop_32Sto64,

	/* Narrowing conversions */
	Iop_64to8, Iop_32to8, Iop_64to16,
	/* 8 <-> 16 bit conversions */
	Iop_16to8, // :: I16 -> I8, low half
	Iop_16HIto8, // :: I16 -> I8, high half
	Iop_8HLto16, // :: (I8,I8) -> I16
	/* 16 <-> 32 bit conversions */
	Iop_32to16, // :: I32 -> I16, low half
	Iop_32HIto16, // :: I32 -> I16, high half
	Iop_16HLto32, // :: (I16,I16) -> I32
	/* 32 <-> 64 bit conversions */
	Iop_64to32, // :: I64 -> I32, low half
	Iop_64HIto32, // :: I64 -> I32, high half
	Iop_32HLto64, // :: (I32,I32) -> I64
	/* 64 <-> 128 bit conversions */
	Iop_128to64, // :: I128 -> I64, low half
	Iop_128HIto64, // :: I128 -> I64, high half
	Iop_64HLto128, // :: (I64,I64) -> I128
	/* 1-bit stuff */
	Iop_Not1, /* :: Ity_Bit -> Ity_Bit */
	Iop_32to1, /* :: Ity_I32 -> Ity_Bit, just select bit[0] */
	Iop_64to1, /* :: Ity_I64 -> Ity_Bit, just select bit[0] */
	Iop_1Uto8, /* :: Ity_Bit -> Ity_I8, unsigned widen */
	Iop_1Uto32, /* :: Ity_Bit -> Ity_I32, unsigned widen */
	Iop_1Uto64, /* :: Ity_Bit -> Ity_I64, unsigned widen */
	Iop_1Sto8, /* :: Ity_Bit -> Ity_I8, signed widen */
	Iop_1Sto16, /* :: Ity_Bit -> Ity_I16, signed widen */
	Iop_1Sto32, /* :: Ity_Bit -> Ity_I32, signed widen */
	Iop_1Sto64, /* :: Ity_Bit -> Ity_I64, signed widen */

	/* ------ Floating point. We try to be IEEE754 compliant. ------ */

	/* --- Simple stuff as mandated by 754. --- */

	/* Binary operations, with rounding. */
	/* :: IRRoundingMode(I32) x F64 x F64 -> F64 */
	Iop_AddF64, Iop_SubF64, Iop_MulF64, Iop_DivF64,

	/* :: IRRoundingMode(I32) x F32 x F32 -> F32 */
	Iop_AddF32, Iop_SubF32, Iop_MulF32, Iop_DivF32,

	/*
	 * Variants of the above which produce a 64-bit result but which round their
	 * result to a IEEE float range first.
	 */
	/* :: IRRoundingMode(I32) x F64 x F64 -> F64 */
	Iop_AddF64r32, Iop_SubF64r32, Iop_MulF64r32, Iop_DivF64r32,

	/* Unary operations, without rounding. */
	/* :: F64 -> F64 */
	Iop_NegF64, Iop_AbsF64,

	/* :: F32 -> F32 */
	Iop_NegF32, Iop_AbsF32,

	/* Unary operations, with rounding. */
	/* :: IRRoundingMode(I32) x F64 -> F64 */
	Iop_SqrtF64,

	/* :: IRRoundingMode(I32) x F32 -> F32 */
	Iop_SqrtF32,

	/*
	 * Comparison, yielding GT/LT/EQ/UN(ordered), as per the following: 0x45
	 * Unordered 0x01 LT 0x00 GT 0x40 EQ This just happens to be the Intel
	 * encoding. The values are recorded in the type IRCmpF64Result.
	 */
	/* :: F64 x F64 -> IRCmpF64Result(I32) */
	Iop_CmpF64, Iop_CmpF32, Iop_CmpF128,

	/* --- Int to/from FP conversions. --- */

	/*
	 * For the most part, these take a first argument :: Ity_I32 (as
	 * IRRoundingMode) which is an indication of the rounding mode to use, as
	 * per the following encoding ("the standard encoding"): 00b to nearest (the
	 * default) 01b to -infinity 10b to +infinity 11b to zero This just happens
	 * to be the Intel encoding. For reference only, the PPC encoding is: 00b to
	 * nearest (the default) 01b to zero 10b to +infinity 11b to -infinity Any
	 * PPC -> IR front end will have to translate these PPC encodings, as
	 * encoded in the guest state, to the standard encodings, to pass to the
	 * primops. For reference only, the ARM VFP encoding is: 00b to nearest 01b
	 * to +infinity 10b to -infinity 11b to zero Again, this will have to be
	 * converted to the standard encoding to pass to primops.
	 * 
	 * If one of these conversions gets an out-of-range condition, or a NaN, as
	 * an argument, the result is host-defined. On x86 the "integer indefinite"
	 * value 0x80..00 is produced. On PPC it is either 0x80..00 or 0x7F..FF
	 * depending on the sign of the argument.
	 * 
	 * On ARMvfp, when converting to a signed integer result, the overflow
	 * result is 0x80..00 for negative args and 0x7F..FF for positive args. For
	 * unsigned integer results it is 0x00..00 and 0xFF..FF respectively.
	 * 
	 * Rounding is required whenever the destination type cannot represent
	 * exactly all values of the source type.
	 */
	Iop_F64toI16S, /* IRRoundingMode(I32) x F64 -> signed I16 */
	Iop_F64toI32S, /* IRRoundingMode(I32) x F64 -> signed I32 */
	Iop_F64toI64S, /* IRRoundingMode(I32) x F64 -> signed I64 */
	Iop_F64toI64U, /* IRRoundingMode(I32) x F64 -> unsigned I64 */

	Iop_F64toI32U, /* IRRoundingMode(I32) x F64 -> unsigned I32 */

	Iop_I32StoF64, /* signed I32 -> F64 */
	Iop_I64StoF64, /* IRRoundingMode(I32) x signed I64 -> F64 */
	Iop_I64UtoF64, /* IRRoundingMode(I32) x unsigned I64 -> F64 */
	Iop_I64UtoF32, /* IRRoundingMode(I32) x unsigned I64 -> F32 */

	Iop_I32UtoF32, /* IRRoundingMode(I32) x unsigned I32 -> F32 */
	Iop_I32UtoF64, /* unsigned I32 -> F64 */

	Iop_F32toI32S, /* IRRoundingMode(I32) x F32 -> signed I32 */
	Iop_F32toI64S, /* IRRoundingMode(I32) x F32 -> signed I64 */
	Iop_F32toI32U, /* IRRoundingMode(I32) x F32 -> unsigned I32 */
	Iop_F32toI64U, /* IRRoundingMode(I32) x F32 -> unsigned I64 */

	Iop_I32StoF32, /* IRRoundingMode(I32) x signed I32 -> F32 */
	Iop_I64StoF32, /* IRRoundingMode(I32) x signed I64 -> F32 */

	/* Conversion between floating point formats */
	Iop_F32toF64, /* F32 -> F64 */
	Iop_F64toF32, /* IRRoundingMode(I32) x F64 -> F32 */

	/*
	 * Reinterpretation. Take an F64 and produce an I64 with the same bit
	 * pattern, or vice versa.
	 */
	Iop_ReinterpF64asI64, Iop_ReinterpI64asF64, Iop_ReinterpF32asI32, Iop_ReinterpI32asF32,

	/* Support for 128-bit floating point */
	Iop_F64HLtoF128, /* (high half of F128,low half of F128) -> F128 */
	Iop_F128HItoF64, /* F128 -> high half of F128 into a F64 register */
	Iop_F128LOtoF64, /* F128 -> low half of F128 into a F64 register */

	/* :: IRRoundingMode(I32) x F128 x F128 -> F128 */
	Iop_AddF128, Iop_SubF128, Iop_MulF128, Iop_DivF128,

	/* :: F128 -> F128 */
	Iop_NegF128, Iop_AbsF128,

	/* :: IRRoundingMode(I32) x F128 -> F128 */
	Iop_SqrtF128,

	Iop_I32StoF128, /* signed I32 -> F128 */
	Iop_I64StoF128, /* signed I64 -> F128 */
	Iop_I32UtoF128, /* unsigned I32 -> F128 */
	Iop_I64UtoF128, /* unsigned I64 -> F128 */
	Iop_F32toF128, /* F32 -> F128 */
	Iop_F64toF128, /* F64 -> F128 */

	Iop_F128toI32S, /* IRRoundingMode(I32) x F128 -> signed I32 */
	Iop_F128toI64S, /* IRRoundingMode(I32) x F128 -> signed I64 */
	Iop_F128toI32U, /* IRRoundingMode(I32) x F128 -> unsigned I32 */
	Iop_F128toI64U, /* IRRoundingMode(I32) x F128 -> unsigned I64 */
	Iop_F128toF64, /* IRRoundingMode(I32) x F128 -> F64 */
	Iop_F128toF32, /* IRRoundingMode(I32) x F128 -> F32 */

	/* --- guest x86/amd64 specifics, not mandated by 754. --- */

	/* Binary ops, with rounding. */
	/* :: IRRoundingMode(I32) x F64 x F64 -> F64 */
	Iop_AtanF64, /* FPATAN, arctan(arg1/arg2) */
	Iop_Yl2xF64, /* FYL2X, arg1 * log2(arg2) */
	Iop_Yl2xp1F64, /* FYL2XP1, arg1 * log2(arg2+1.0) */
	Iop_PRemF64, /* FPREM, non-IEEE remainder(arg1/arg2) */
	Iop_PRemC3210F64, /* C3210 flags resulting from FPREM, :: I32 */
	Iop_PRem1F64, /* FPREM1, IEEE remainder(arg1/arg2) */
	Iop_PRem1C3210F64, /* C3210 flags resulting from FPREM1, :: I32 */
	Iop_ScaleF64, /* FSCALE, arg1 * (2^RoundTowardsZero(arg2)) */
	/*
	 * Note that on x86 guest, PRem1{C3210} has the same behaviour as the IEEE
	 * mandated RemF64, except it is limited in the range of its operand. Hence
	 * the partialness.
	 */

	/* Unary ops, with rounding. */
	/* :: IRRoundingMode(I32) x F64 -> F64 */
	Iop_SinF64, /* FSIN */
	Iop_CosF64, /* FCOS */
	Iop_TanF64, /* FTAN */
	Iop_2xm1F64, /* (2^arg - 1.0) */
	Iop_RoundF64toInt, /*
						 * F64 value to nearest integral value (still as F64)
						 */
	Iop_RoundF32toInt, /*
						 * F32 value to nearest integral value (still as F32)
						 */

	/* --- guest s390 specifics, not mandated by 754. --- */

	/* Fused multiply-add/sub */
	/*
	 * :: IRRoundingMode(I32) x F32 x F32 x F32 -> F32 (computes arg2 * arg3 +/-
	 * arg4)
	 */
	Iop_MAddF32, Iop_MSubF32,

	/* --- guest ppc32/64 specifics, not mandated by 754. --- */

	/* Ternary operations, with rounding. */
	/*
	 * Fused multiply-add/sub, with 112-bit intermediate precision for ppc. Also
	 * used to implement fused multiply-add/sub for s390.
	 */
	/*
	 * :: IRRoundingMode(I32) x F64 x F64 x F64 -> F64 (computes arg2 * arg3 +/-
	 * arg4)
	 */
	Iop_MAddF64, Iop_MSubF64,

	/*
	 * Variants of the above which produce a 64-bit result but which round their
	 * result to a IEEE float range first.
	 */
	/* :: IRRoundingMode(I32) x F64 x F64 x F64 -> F64 */
	Iop_MAddF64r32, Iop_MSubF64r32,

	/* :: F64 -> F64 */
	Iop_RSqrtEst5GoodF64, /* reciprocal square root estimate, 5 good bits */
	Iop_RoundF64toF64_NEAREST, /* frin */
	Iop_RoundF64toF64_NegINF, /* frim */
	Iop_RoundF64toF64_PosINF, /* frip */
	Iop_RoundF64toF64_ZERO, /* friz */

	/* :: F64 -> F32 */
	Iop_TruncF64asF32, /* do F64->F32 truncation as per 'fsts' */

	/* :: IRRoundingMode(I32) x F64 -> F64 */
	Iop_RoundF64toF32, /* round F64 to nearest F32 value (still as F64) */
	/*
	 * NB: pretty much the same as Iop_F64toF32, except no change of type.
	 */

	/* --- guest arm64 specifics, not mandated by 754. --- */

	Iop_RecpExpF64, /* FRECPX d :: IRRoundingMode(I32) x F64 -> F64 */
	Iop_RecpExpF32, /* FRECPX s :: IRRoundingMode(I32) x F32 -> F32 */

	/* ------------------ 16-bit scalar FP ------------------ */

	Iop_F16toF64, /* F16 -> F64 */
	Iop_F64toF16, /* IRRoundingMode(I32) x F64 -> F16 */

	Iop_F16toF32, /* F16 -> F32 */
	Iop_F32toF16, /* IRRoundingMode(I32) x F32 -> F16 */

	/* ------------------ 32-bit SIMD Integer ------------------ */

	/* 32x1 saturating add/sub (ok, well, not really SIMD :) */
	Iop_QAdd32S, Iop_QSub32S,

	/* 16x2 add/sub, also signed/unsigned saturating variants */
	Iop_Add16x2, Iop_Sub16x2, Iop_QAdd16Sx2, Iop_QAdd16Ux2, Iop_QSub16Sx2, Iop_QSub16Ux2,

	/*
	 * 16x2 signed/unsigned halving add/sub. For each lane, these compute bits
	 * 16:1 of (eg) sx(argL) + sx(argR), or zx(argL) - zx(argR) etc.
	 */
	Iop_HAdd16Ux2, Iop_HAdd16Sx2, Iop_HSub16Ux2, Iop_HSub16Sx2,

	/* 8x4 add/sub, also signed/unsigned saturating variants */
	Iop_Add8x4, Iop_Sub8x4, Iop_QAdd8Sx4, Iop_QAdd8Ux4, Iop_QSub8Sx4, Iop_QSub8Ux4,

	/*
	 * 8x4 signed/unsigned halving add/sub. For each lane, these compute bits
	 * 8:1 of (eg) sx(argL) + sx(argR), or zx(argL) - zx(argR) etc.
	 */
	Iop_HAdd8Ux4, Iop_HAdd8Sx4, Iop_HSub8Ux4, Iop_HSub8Sx4,

	/* 8x4 sum of absolute unsigned differences. */
	Iop_Sad8Ux4,

	/* MISC (vector integer cmp != 0) */
	Iop_CmpNEZ16x2, Iop_CmpNEZ8x4,

	/* ------------------ 64-bit SIMD FP ------------------------ */

	/* Convertion to/from int */
	Iop_I32UtoFx2, Iop_I32StoFx2, /* I32x4 -> F32x4 */
	Iop_FtoI32Ux2_RZ, Iop_FtoI32Sx2_RZ, /* F32x4 -> I32x4 */
	/*
	 * Fixed32 format is floating-point number with fixed number of fraction
	 * bits. The number of fraction bits is passed as a second argument of type
	 * I8.
	 */
	Iop_F32ToFixed32Ux2_RZ, Iop_F32ToFixed32Sx2_RZ, /* fp -> fixed-point */
	Iop_Fixed32UToF32x2_RN, Iop_Fixed32SToF32x2_RN, /* fixed-point -> fp */

	/* Binary operations */
	Iop_Max32Fx2, Iop_Min32Fx2,
	/*
	 * Pairwise Min and Max. See integer pairwise operations for more details.
	 */
	Iop_PwMax32Fx2, Iop_PwMin32Fx2,
	/*
	 * Note: For the following compares, the arm front-end assumes a nan in a
	 * lane of either argument returns zero for that lane.
	 */
	Iop_CmpEQ32Fx2, Iop_CmpGT32Fx2, Iop_CmpGE32Fx2,

	/*
	 * Vector Reciprocal Estimate finds an approximate reciprocal of each
	 * element in the operand vector, and places the results in the destination
	 * vector.
	 */
	Iop_RecipEst32Fx2,

	/*
	 * Vector Reciprocal Step computes (2.0 - arg1 * arg2). Note, that if one of
	 * the arguments is zero and another one is infinity of arbitrary sign the
	 * result of the operation is 2.0.
	 */
	Iop_RecipStep32Fx2,

	/*
	 * Vector Reciprocal Square Root Estimate finds an approximate reciprocal
	 * square root of each element in the operand vector.
	 */
	Iop_RSqrtEst32Fx2,

	/*
	 * Vector Reciprocal Square Root Step computes (3.0 - arg1 * arg2) / 2.0.
	 * Note, that of one of the arguments is zero and another one is infiinty of
	 * arbitrary sign the result of the operation is 1.5.
	 */
	Iop_RSqrtStep32Fx2,

	/* Unary */
	Iop_Neg32Fx2, Iop_Abs32Fx2,

	/* ------------------ 64-bit SIMD Integer. ------------------ */

	/* MISC (vector integer cmp != 0) */
	Iop_CmpNEZ8x8, Iop_CmpNEZ16x4, Iop_CmpNEZ32x2,

	/* ADDITION (normal / unsigned sat / signed sat) */
	Iop_Add8x8, Iop_Add16x4, Iop_Add32x2, Iop_QAdd8Ux8, Iop_QAdd16Ux4, Iop_QAdd32Ux2, Iop_QAdd64Ux1, Iop_QAdd8Sx8, Iop_QAdd16Sx4, Iop_QAdd32Sx2, Iop_QAdd64Sx1,

	/* PAIRWISE operations */
	/*
	 * Iop_PwFoo16x4( [a,b,c,d], [e,f,g,h] ) = [Foo16(a,b), Foo16(c,d),
	 * Foo16(e,f), Foo16(g,h)]
	 */
	Iop_PwAdd8x8, Iop_PwAdd16x4, Iop_PwAdd32x2, Iop_PwMax8Sx8, Iop_PwMax16Sx4, Iop_PwMax32Sx2, Iop_PwMax8Ux8, Iop_PwMax16Ux4, Iop_PwMax32Ux2, Iop_PwMin8Sx8, Iop_PwMin16Sx4, Iop_PwMin32Sx2, Iop_PwMin8Ux8, Iop_PwMin16Ux4, Iop_PwMin32Ux2,
	/*
	 * Longening variant is unary. The resulting vector contains two times less
	 * elements than operand, but they are two times wider. Example:
	 * Iop_PAddL16Ux4( [a,b,c,d] ) = [a+b,c+d] where a+b and c+d are unsigned
	 * 32-bit values.
	 */
	Iop_PwAddL8Ux8, Iop_PwAddL16Ux4, Iop_PwAddL32Ux2, Iop_PwAddL8Sx8, Iop_PwAddL16Sx4, Iop_PwAddL32Sx2,

	/* SUBTRACTION (normal / unsigned sat / signed sat) */
	Iop_Sub8x8, Iop_Sub16x4, Iop_Sub32x2, Iop_QSub8Ux8, Iop_QSub16Ux4, Iop_QSub32Ux2, Iop_QSub64Ux1, Iop_QSub8Sx8, Iop_QSub16Sx4, Iop_QSub32Sx2, Iop_QSub64Sx1,

	/* ABSOLUTE VALUE */
	Iop_Abs8x8, Iop_Abs16x4, Iop_Abs32x2,

	/*
	 * MULTIPLICATION (normal / high half of signed/unsigned / plynomial )
	 */
	Iop_Mul8x8, Iop_Mul16x4, Iop_Mul32x2, Iop_Mul32Fx2, Iop_MulHi16Ux4, Iop_MulHi16Sx4,
	/*
	 * Plynomial multiplication treats it's arguments as coefficients of
	 * polynoms over {0, 1}.
	 */
	Iop_PolynomialMul8x8,

	/*
	 * Vector Saturating Doubling Multiply Returning High Half and Vector
	 * Saturating Rounding Doubling Multiply Returning High Half
	 */
	/*
	 * These IROp's multiply corresponding elements in two vectors, double the
	 * results, and place the most significant half of the final results in the
	 * destination vector. The results are truncated or rounded. If any of the
	 * results overflow, they are saturated.
	 */
	Iop_QDMulHi16Sx4, Iop_QDMulHi32Sx2, Iop_QRDMulHi16Sx4, Iop_QRDMulHi32Sx2,

	/* AVERAGING: note: (arg1 + arg2 + 1) >>u 1 */
	Iop_Avg8Ux8, Iop_Avg16Ux4,

	/* MIN/MAX */
	Iop_Max8Sx8, Iop_Max16Sx4, Iop_Max32Sx2, Iop_Max8Ux8, Iop_Max16Ux4, Iop_Max32Ux2, Iop_Min8Sx8, Iop_Min16Sx4, Iop_Min32Sx2, Iop_Min8Ux8, Iop_Min16Ux4, Iop_Min32Ux2,

	/* COMPARISON */
	Iop_CmpEQ8x8, Iop_CmpEQ16x4, Iop_CmpEQ32x2, Iop_CmpGT8Ux8, Iop_CmpGT16Ux4, Iop_CmpGT32Ux2, Iop_CmpGT8Sx8, Iop_CmpGT16Sx4, Iop_CmpGT32Sx2,

	/*
	 * COUNT ones / leading zeroes / leading sign bits (not including topmost
	 * bit)
	 */
	Iop_Cnt8x8, Iop_Clz8x8, Iop_Clz16x4, Iop_Clz32x2, Iop_Cls8x8, Iop_Cls16x4, Iop_Cls32x2, Iop_Clz64x2,

	/* VECTOR x VECTOR SHIFT / ROTATE */
	Iop_Shl8x8, Iop_Shl16x4, Iop_Shl32x2, Iop_Shr8x8, Iop_Shr16x4, Iop_Shr32x2, Iop_Sar8x8, Iop_Sar16x4, Iop_Sar32x2, Iop_Sal8x8, Iop_Sal16x4, Iop_Sal32x2, Iop_Sal64x1,

	/* VECTOR x SCALAR SHIFT (shift amt :: Ity_I8) */
	Iop_ShlN8x8, Iop_ShlN16x4, Iop_ShlN32x2, Iop_ShrN8x8, Iop_ShrN16x4, Iop_ShrN32x2, Iop_SarN8x8, Iop_SarN16x4, Iop_SarN32x2,

	/* VECTOR x VECTOR SATURATING SHIFT */
	Iop_QShl8x8, Iop_QShl16x4, Iop_QShl32x2, Iop_QShl64x1, Iop_QSal8x8, Iop_QSal16x4, Iop_QSal32x2, Iop_QSal64x1,
	/* VECTOR x INTEGER SATURATING SHIFT */
	Iop_QShlNsatSU8x8, Iop_QShlNsatSU16x4, Iop_QShlNsatSU32x2, Iop_QShlNsatSU64x1, Iop_QShlNsatUU8x8, Iop_QShlNsatUU16x4, Iop_QShlNsatUU32x2, Iop_QShlNsatUU64x1, Iop_QShlNsatSS8x8, Iop_QShlNsatSS16x4, Iop_QShlNsatSS32x2, Iop_QShlNsatSS64x1,

	/*
	 * NARROWING (binary) -- narrow 2xI64 into 1xI64, hi half from left arg
	 */
	/*
	 * For saturated narrowing, I believe there are 4 variants of the basic
	 * arithmetic operation, depending on the signedness of argument and result.
	 * Here are examples that exemplify what I mean:
	 * 
	 * QNarrow16Uto8U ( UShort x ) if (x >u 255) x = 255; return x[7:0];
	 * 
	 * QNarrow16Sto8S ( Short x ) if (x <s -128) x = -128; if (x >s 127) x =
	 * 127; return x[7:0];
	 * 
	 * QNarrow16Uto8S ( UShort x ) if (x >u 127) x = 127; return x[7:0];
	 * 
	 * QNarrow16Sto8U ( Short x ) if (x <s 0) x = 0; if (x >s 255) x = 255;
	 * return x[7:0];
	 */
	Iop_QNarrowBin16Sto8Ux8, Iop_QNarrowBin16Sto8Sx8, Iop_QNarrowBin32Sto16Sx4, Iop_NarrowBin16to8x8, Iop_NarrowBin32to16x4,

	/* INTERLEAVING */
	/*
	 * Interleave lanes from low or high halves of operands. Most-significant
	 * result lane is from the left arg.
	 */
	Iop_InterleaveHI8x8, Iop_InterleaveHI16x4, Iop_InterleaveHI32x2, Iop_InterleaveLO8x8, Iop_InterleaveLO16x4, Iop_InterleaveLO32x2,
	/*
	 * Interleave odd/even lanes of operands. Most-significant result lane is
	 * from the left arg. Note that Interleave{Odd,Even}Lanes32x2 are identical
	 * to Interleave{HI,LO}32x2 and so are omitted.
	 */
	Iop_InterleaveOddLanes8x8, Iop_InterleaveEvenLanes8x8, Iop_InterleaveOddLanes16x4, Iop_InterleaveEvenLanes16x4,

	/*
	 * CONCATENATION -- build a new value by concatenating either the even or
	 * odd lanes of both operands. Note that Cat{Odd,Even}Lanes32x2 are
	 * identical to Interleave{HI,LO}32x2 and so are omitted.
	 */
	Iop_CatOddLanes8x8, Iop_CatOddLanes16x4, Iop_CatEvenLanes8x8, Iop_CatEvenLanes16x4,

	/*
	 * GET / SET elements of VECTOR GET is binop (I64, I8) -> I<elem_size> SET
	 * is triop (I64, I8, I<elem_size>) -> I64
	 */
	/* Note: the arm back-end handles only constant second argument */
	Iop_GetElem8x8, Iop_GetElem16x4, Iop_GetElem32x2, Iop_SetElem8x8, Iop_SetElem16x4, Iop_SetElem32x2,

	/* DUPLICATING -- copy value to all lanes */
	Iop_Dup8x8, Iop_Dup16x4, Iop_Dup32x2,

	/*
	 * SLICE -- produces the lowest 64 bits of (arg1:arg2) >> (8 * arg3). arg3
	 * is a shift amount in bytes and may be between 0 and 8 inclusive. When 0,
	 * the result is arg2; when 8, the result is arg1. Not all back ends handle
	 * all values. The arm32 and arm64 back ends handle only immediate arg3
	 * values.
	 */
	Iop_Slice64, // (I64, I64, I8) -> I64

	/*
	 * REVERSE the order of chunks in vector lanes. Chunks must be smaller than
	 * the vector lanes (obviously) and so may be 8-, 16- and 32-bit in size.
	 */
	/*
	 * Examples: Reverse8sIn16_x4([a,b,c,d,e,f,g,h]) = [b,a,d,c,f,e,h,g]
	 * Reverse8sIn32_x2([a,b,c,d,e,f,g,h]) = [d,c,b,a,h,g,f,e]
	 * Reverse8sIn64_x1([a,b,c,d,e,f,g,h]) = [h,g,f,e,d,c,b,a]
	 */
	Iop_Reverse8sIn16_x4, Iop_Reverse8sIn32_x2, Iop_Reverse16sIn32_x2, Iop_Reverse8sIn64_x1, Iop_Reverse16sIn64_x1, Iop_Reverse32sIn64_x1,

	/*
	 * PERMUTING -- copy src bytes to dst, as indexed by control vector bytes:
	 * for i in 0 .. 7 . result[i] = argL[ argR[i] ] argR[i] values may only be
	 * in the range 0 .. 7, else behaviour is undefined.
	 */
	Iop_Perm8x8,

	/*
	 * MISC CONVERSION -- get high bits of each byte lane, a la x86/amd64
	 * pmovmskb
	 */
	Iop_GetMSBs8x8, /* I64 -> I8 */

	/*
	 * Vector Reciprocal Estimate and Vector Reciprocal Square Root Estimate See
	 * floating-point equivalents for details.
	 */
	Iop_RecipEst32Ux2, Iop_RSqrtEst32Ux2,

	/* ------------------ Decimal Floating Point ------------------ */

	/*
	 * ARITHMETIC INSTRUCTIONS 64-bit ----------------------------------
	 * IRRoundingMode(I32) X D64 X D64 -> D64
	 */
	Iop_AddD64, Iop_SubD64, Iop_MulD64, Iop_DivD64,

	/*
	 * ARITHMETIC INSTRUCTIONS 128-bit ----------------------------------
	 * IRRoundingMode(I32) X D128 X D128 -> D128
	 */
	Iop_AddD128, Iop_SubD128, Iop_MulD128, Iop_DivD128,

	/*
	 * SHIFT SIGNIFICAND INSTRUCTIONS The DFP significand is shifted by the
	 * number of digits specified by the U8 operand. Digits shifted out of the
	 * leftmost digit are lost. Zeros are supplied to the vacated positions on
	 * the right. The sign of the result is the same as the sign of the original
	 * operand.
	 *
	 * D64 x U8 -> D64 left shift and right shift respectively
	 */
	Iop_ShlD64, Iop_ShrD64,

	/* D128 x U8 -> D128 left shift and right shift respectively */
	Iop_ShlD128, Iop_ShrD128,

	/*
	 * FORMAT CONVERSION INSTRUCTIONS D32 -> D64
	 */
	Iop_D32toD64,

	/* D64 -> D128 */
	Iop_D64toD128,

	/* I32S -> D128 */
	Iop_I32StoD128,

	/* I32U -> D128 */
	Iop_I32UtoD128,

	/* I64S -> D128 */
	Iop_I64StoD128,

	/* I64U -> D128 */
	Iop_I64UtoD128,

	/* IRRoundingMode(I32) x D64 -> D32 */
	Iop_D64toD32,

	/* IRRoundingMode(I32) x D128 -> D64 */
	Iop_D128toD64,

	/* I32S -> D64 */
	Iop_I32StoD64,

	/* I32U -> D64 */
	Iop_I32UtoD64,

	/* IRRoundingMode(I32) x I64 -> D64 */
	Iop_I64StoD64,

	/* IRRoundingMode(I32) x I64 -> D64 */
	Iop_I64UtoD64,

	/* IRRoundingMode(I32) x D64 -> I32 */
	Iop_D64toI32S,

	/* IRRoundingMode(I32) x D64 -> I32 */
	Iop_D64toI32U,

	/* IRRoundingMode(I32) x D64 -> I64 */
	Iop_D64toI64S,

	/* IRRoundingMode(I32) x D64 -> I64 */
	Iop_D64toI64U,

	/* IRRoundingMode(I32) x D128 -> I32 */
	Iop_D128toI32S,

	/* IRRoundingMode(I32) x D128 -> I32 */
	Iop_D128toI32U,

	/* IRRoundingMode(I32) x D128 -> I64 */
	Iop_D128toI64S,

	/* IRRoundingMode(I32) x D128 -> I64 */
	Iop_D128toI64U,

	/* IRRoundingMode(I32) x F32 -> D32 */
	Iop_F32toD32,

	/* IRRoundingMode(I32) x F32 -> D64 */
	Iop_F32toD64,

	/* IRRoundingMode(I32) x F32 -> D128 */
	Iop_F32toD128,

	/* IRRoundingMode(I32) x F64 -> D32 */
	Iop_F64toD32,

	/* IRRoundingMode(I32) x F64 -> D64 */
	Iop_F64toD64,

	/* IRRoundingMode(I32) x F64 -> D128 */
	Iop_F64toD128,

	/* IRRoundingMode(I32) x F128 -> D32 */
	Iop_F128toD32,

	/* IRRoundingMode(I32) x F128 -> D64 */
	Iop_F128toD64,

	/* IRRoundingMode(I32) x F128 -> D128 */
	Iop_F128toD128,

	/* IRRoundingMode(I32) x D32 -> F32 */
	Iop_D32toF32,

	/* IRRoundingMode(I32) x D32 -> F64 */
	Iop_D32toF64,

	/* IRRoundingMode(I32) x D32 -> F128 */
	Iop_D32toF128,

	/* IRRoundingMode(I32) x D64 -> F32 */
	Iop_D64toF32,

	/* IRRoundingMode(I32) x D64 -> F64 */
	Iop_D64toF64,

	/* IRRoundingMode(I32) x D64 -> F128 */
	Iop_D64toF128,

	/* IRRoundingMode(I32) x D128 -> F32 */
	Iop_D128toF32,

	/* IRRoundingMode(I32) x D128 -> F64 */
	Iop_D128toF64,

	/* IRRoundingMode(I32) x D128 -> F128 */
	Iop_D128toF128,

	/*
	 * ROUNDING INSTRUCTIONS IRRoundingMode(I32) x D64 -> D64 The D64 operand,
	 * if a finite number, it is rounded to a floating point integer value, i.e.
	 * no fractional part.
	 */
	Iop_RoundD64toInt,

	/* IRRoundingMode(I32) x D128 -> D128 */
	Iop_RoundD128toInt,

	/*
	 * COMPARE INSTRUCTIONS D64 x D64 -> IRCmpD64Result(I32)
	 */
	Iop_CmpD64,

	/* D128 x D128 -> IRCmpD128Result(I32) */
	Iop_CmpD128,

	/*
	 * COMPARE BIASED EXPONENET INSTRUCTIONS D64 x D64 -> IRCmpD64Result(I32)
	 */
	Iop_CmpExpD64,

	/* D128 x D128 -> IRCmpD128Result(I32) */
	Iop_CmpExpD128,

	/*
	 * QUANTIZE AND ROUND INSTRUCTIONS The source operand is converted and
	 * rounded to the form with the immediate exponent specified by the rounding
	 * and exponent parameter.
	 *
	 * The second operand is converted and rounded to the form of the first
	 * operand's exponent and the rounded based on the specified rounding mode
	 * parameter.
	 *
	 * IRRoundingMode(I32) x D64 x D64-> D64
	 */
	Iop_QuantizeD64,

	/* IRRoundingMode(I32) x D128 x D128 -> D128 */
	Iop_QuantizeD128,

	/*
	 * IRRoundingMode(I32) x I8 x D64 -> D64 The Decimal Floating point operand
	 * is rounded to the requested significance given by the I8 operand as
	 * specified by the rounding mode.
	 */
	Iop_SignificanceRoundD64,

	/* IRRoundingMode(I32) x I8 x D128 -> D128 */
	Iop_SignificanceRoundD128,

	/*
	 * EXTRACT AND INSERT INSTRUCTIONS D64 -> I64 The exponent of the D32 or D64
	 * operand is extracted. The extracted exponent is converted to a 64-bit
	 * signed binary integer.
	 */
	Iop_ExtractExpD64,

	/* D128 -> I64 */
	Iop_ExtractExpD128,

	/*
	 * D64 -> I64 The number of significand digits of the D64 operand is
	 * extracted. The number is stored as a 64-bit signed binary integer.
	 */
	Iop_ExtractSigD64,

	/* D128 -> I64 */
	Iop_ExtractSigD128,

	/*
	 * I64 x D64 -> D64 The exponent is specified by the first I64 operand the
	 * signed significand is given by the second I64 value. The result is a D64
	 * value consisting of the specified significand and exponent whose sign is
	 * that of the specified significand.
	 */
	Iop_InsertExpD64,

	/* I64 x D128 -> D128 */
	Iop_InsertExpD128,

	/* Support for 128-bit DFP type */
	Iop_D64HLtoD128, Iop_D128HItoD64, Iop_D128LOtoD64,

	/*
	 * I64 -> I64 Convert 50-bit densely packed BCD string to 60 bit BCD string
	 */
	Iop_DPBtoBCD,

	/*
	 * I64 -> I64 Convert 60 bit BCD string to 50-bit densely packed BCD string
	 */
	Iop_BCDtoDPB,

	/*
	 * BCD arithmetic instructions, (V128, V128) -> V128 The BCD format is the
	 * same as that used in the BCD<->DPB conversion routines, except using 124
	 * digits (vs 60) plus the trailing 4-bit signed code.
	 */
	Iop_BCDAdd, Iop_BCDSub,

	/* Conversion I64 -> D64 */
	Iop_ReinterpI64asD64,

	/* Conversion D64 -> I64 */
	Iop_ReinterpD64asI64,

	/* ------------------ 128-bit SIMD FP. ------------------ */

	/* --- 32x4 vector FP --- */

	/* ternary :: IRRoundingMode(I32) x V128 x V128 -> V128 */
	Iop_Add32Fx4, Iop_Sub32Fx4, Iop_Mul32Fx4, Iop_Div32Fx4,

	/* binary */
	Iop_Max32Fx4, Iop_Min32Fx4, Iop_Add32Fx2, Iop_Sub32Fx2,
	/*
	 * Note: For the following compares, the ppc and arm front-ends assume a nan
	 * in a lane of either argument returns zero for that lane.
	 */
	Iop_CmpEQ32Fx4, Iop_CmpLT32Fx4, Iop_CmpLE32Fx4, Iop_CmpUN32Fx4, Iop_CmpGT32Fx4, Iop_CmpGE32Fx4,

	/* Pairwise Max and Min. See integer pairwise operations for details. */
	Iop_PwMax32Fx4, Iop_PwMin32Fx4,

	/* unary */
	Iop_Abs32Fx4, Iop_Neg32Fx4,

	/* binary :: IRRoundingMode(I32) x V128 -> V128 */
	Iop_Sqrt32Fx4,

	/*
	 * Vector Reciprocal Estimate finds an approximate reciprocal of each
	 * element in the operand vector, and places the results in the destination
	 * vector.
	 */
	Iop_RecipEst32Fx4,

	/*
	 * Vector Reciprocal Step computes (2.0 - arg1 * arg2). Note, that if one of
	 * the arguments is zero and another one is infinity of arbitrary sign the
	 * result of the operation is 2.0.
	 */
	Iop_RecipStep32Fx4,

	/*
	 * Vector Reciprocal Square Root Estimate finds an approximate reciprocal
	 * square root of each element in the operand vector.
	 */
	Iop_RSqrtEst32Fx4,

	/*
	 * Vector Reciprocal Square Root Step computes (3.0 - arg1 * arg2) / 2.0.
	 * Note, that of one of the arguments is zero and another one is infiinty of
	 * arbitrary sign the result of the operation is 1.5.
	 */
	Iop_RSqrtStep32Fx4,

	/* --- Int to/from FP conversion --- */
	/*
	 * Unlike the standard fp conversions, these irops take no rounding mode
	 * argument. Instead the irop trailers _R{M,P,N,Z} indicate the mode: {-inf,
	 * +inf, nearest, zero} respectively.
	 */
	Iop_I32UtoFx4, Iop_I32StoFx4, /* I32x4 -> F32x4 */
	Iop_FtoI32Ux4_RZ, Iop_FtoI32Sx4_RZ, /* F32x4 -> I32x4 */
	Iop_QFtoI32Ux4_RZ, Iop_QFtoI32Sx4_RZ, /* F32x4 -> I32x4 (saturating) */
	Iop_RoundF32x4_RM, Iop_RoundF32x4_RP, /* round to fp integer */
	Iop_RoundF32x4_RN, Iop_RoundF32x4_RZ, /* round to fp integer */
	/*
	 * Fixed32 format is floating-point number with fixed number of fraction
	 * bits. The number of fraction bits is passed as a second argument of type
	 * I8.
	 */
	Iop_F32ToFixed32Ux4_RZ, Iop_F32ToFixed32Sx4_RZ, /* fp -> fixed-point */
	Iop_Fixed32UToF32x4_RN, Iop_Fixed32SToF32x4_RN, /* fixed-point -> fp */

	/* --- Single to/from half conversion --- */
	/* FIXME: what kind of rounding in F32x4 -> F16x4 case? */
	Iop_F32toF16x4, Iop_F16toF32x4, /* F32x4 <-> F16x4 */

	/* --- 32x4 lowest-lane-only scalar FP --- */

	/*
	 * In binary cases, upper 3/4 is copied from first operand. In unary cases,
	 * upper 3/4 is copied from the operand.
	 */

	/* binary */
	Iop_Add32F0x4, Iop_Sub32F0x4, Iop_Mul32F0x4, Iop_Div32F0x4, Iop_Max32F0x4, Iop_Min32F0x4, Iop_CmpEQ32F0x4, Iop_CmpLT32F0x4, Iop_CmpLE32F0x4, Iop_CmpUN32F0x4,

	/* unary */
	Iop_RecipEst32F0x4, Iop_Sqrt32F0x4, Iop_RSqrtEst32F0x4,

	/* --- 64x2 vector FP --- */

	/* ternary :: IRRoundingMode(I32) x V128 x V128 -> V128 */
	Iop_Add64Fx2, Iop_Sub64Fx2, Iop_Mul64Fx2, Iop_Div64Fx2,

	/* binary */
	Iop_Max64Fx2, Iop_Min64Fx2, Iop_CmpEQ64Fx2, Iop_CmpLT64Fx2, Iop_CmpLE64Fx2, Iop_CmpUN64Fx2,

	/* unary */
	Iop_Abs64Fx2, Iop_Neg64Fx2,

	/* binary :: IRRoundingMode(I32) x V128 -> V128 */
	Iop_Sqrt64Fx2,

	/* see 32Fx4 variants for description */
	Iop_RecipEst64Fx2, // unary
	Iop_RecipStep64Fx2, // binary
	Iop_RSqrtEst64Fx2, // unary
	Iop_RSqrtStep64Fx2, // binary

	/* --- 64x2 lowest-lane-only scalar FP --- */

	/*
	 * In binary cases, upper half is copied from first operand. In unary cases,
	 * upper half is copied from the operand.
	 */

	/* binary */
	Iop_Add64F0x2, Iop_Sub64F0x2, Iop_Mul64F0x2, Iop_Div64F0x2, Iop_Max64F0x2, Iop_Min64F0x2, Iop_CmpEQ64F0x2, Iop_CmpLT64F0x2, Iop_CmpLE64F0x2, Iop_CmpUN64F0x2,

	/* unary */
	Iop_Sqrt64F0x2,

	/* --- pack / unpack --- */

	/* 64 <-> 128 bit vector */
	Iop_V128to64, // :: V128 -> I64, low half
	Iop_V128HIto64, // :: V128 -> I64, high half
	Iop_64HLtoV128, // :: (I64,I64) -> V128

	Iop_64UtoV128, Iop_SetV128lo64,

	/* Copies lower 64/32/16/8 bits, zeroes out the rest. */
	Iop_ZeroHI64ofV128, // :: V128 -> V128
	Iop_ZeroHI96ofV128, // :: V128 -> V128
	Iop_ZeroHI112ofV128, // :: V128 -> V128
	Iop_ZeroHI120ofV128, // :: V128 -> V128

	/* 32 <-> 128 bit vector */
	Iop_32UtoV128, Iop_V128to32, // :: V128 -> I32, lowest lane
	Iop_SetV128lo32, // :: (V128,I32) -> V128

	/* ------------------ 128-bit SIMD Integer. ------------------ */

	/* BITWISE OPS */
	Iop_NotV128, Iop_AndV128, Iop_OrV128, Iop_XorV128,

	/* VECTOR SHIFT (shift amt :: Ity_I8) */
	Iop_ShlV128, Iop_ShrV128,

	/* MISC (vector integer cmp != 0) */
	Iop_CmpNEZ8x16, Iop_CmpNEZ16x8, Iop_CmpNEZ32x4, Iop_CmpNEZ64x2,

	/* ADDITION (normal / U->U sat / S->S sat) */
	Iop_Add8x16, Iop_Add16x8, Iop_Add32x4, Iop_Add64x2, Iop_QAdd8Ux16, Iop_QAdd16Ux8, Iop_QAdd32Ux4, Iop_QAdd64Ux2, Iop_QAdd8Sx16, Iop_QAdd16Sx8, Iop_QAdd32Sx4, Iop_QAdd64Sx2,

	/* ADDITION, ARM64 specific saturating variants. */
	/*
	 * Unsigned widen left arg, signed widen right arg, add, saturate S->S. This
	 * corresponds to SUQADD.
	 */
	Iop_QAddExtUSsatSS8x16, Iop_QAddExtUSsatSS16x8, Iop_QAddExtUSsatSS32x4, Iop_QAddExtUSsatSS64x2,
	/*
	 * Signed widen left arg, unsigned widen right arg, add, saturate U->U. This
	 * corresponds to USQADD.
	 */
	Iop_QAddExtSUsatUU8x16, Iop_QAddExtSUsatUU16x8, Iop_QAddExtSUsatUU32x4, Iop_QAddExtSUsatUU64x2,

	/* SUBTRACTION (normal / unsigned sat / signed sat) */
	Iop_Sub8x16, Iop_Sub16x8, Iop_Sub32x4, Iop_Sub64x2, Iop_QSub8Ux16, Iop_QSub16Ux8, Iop_QSub32Ux4, Iop_QSub64Ux2, Iop_QSub8Sx16, Iop_QSub16Sx8, Iop_QSub32Sx4, Iop_QSub64Sx2,

	/* MULTIPLICATION (normal / high half of signed/unsigned) */
	Iop_Mul8x16, Iop_Mul16x8, Iop_Mul32x4, Iop_MulHi16Ux8, Iop_MulHi32Ux4, Iop_MulHi16Sx8, Iop_MulHi32Sx4,
	/* (widening signed/unsigned of even lanes, with lowest lane=zero) */
	Iop_MullEven8Ux16, Iop_MullEven16Ux8, Iop_MullEven32Ux4, Iop_MullEven8Sx16, Iop_MullEven16Sx8, Iop_MullEven32Sx4,

	/* Widening multiplies, all of the form (I64, I64) -> V128 */
	Iop_Mull8Ux8, Iop_Mull8Sx8, Iop_Mull16Ux4, Iop_Mull16Sx4, Iop_Mull32Ux2, Iop_Mull32Sx2,

	/* Signed doubling saturating widening multiplies, (I64, I64) -> V128 */
	Iop_QDMull16Sx4, Iop_QDMull32Sx2,

	/*
	 * Vector Saturating Doubling Multiply Returning High Half and Vector
	 * Saturating Rounding Doubling Multiply Returning High Half. These IROps
	 * multiply corresponding elements in two vectors, double the results, and
	 * place the most significant half of the final results in the destination
	 * vector. The results are truncated or rounded. If any of the results
	 * overflow, they are saturated. To be more precise, for each lane, the
	 * computed result is: QDMulHi: hi-half( sign-extend(laneL) *q
	 * sign-extend(laneR) *q 2 ) QRDMulHi: hi-half( sign-extend(laneL) *q
	 * sign-extend(laneR) *q 2 +q (1 << (lane-width-in-bits - 1)) )
	 */
	Iop_QDMulHi16Sx8, Iop_QDMulHi32Sx4, /* (V128, V128) -> V128 */
	Iop_QRDMulHi16Sx8, Iop_QRDMulHi32Sx4, /* (V128, V128) -> V128 */

	/*
	 * Polynomial multiplication treats its arguments as coefficients of
	 * polynomials over {0, 1}.
	 */
	Iop_PolynomialMul8x16, /* (V128, V128) -> V128 */
	Iop_PolynomialMull8x8, /* (I64, I64) -> V128 */

	/*
	 * Vector Polynomial multiplication add. (V128, V128) -> V128
	 *** 
	 * Below is the algorithm for the instructions. These Iops could be emulated
	 * to get this functionality, but the emulation would be long and messy.
	 * 
	 * Example for polynomial multiply add for vector of bytes do i = 0 to 15
	 * prod[i].bit[0:14] <- 0 srcA <- VR[argL].byte[i] srcB <- VR[argR].byte[i]
	 * do j = 0 to 7 do k = 0 to j gbit <- srcA.bit[k] & srcB.bit[j-k]
	 * prod[i].bit[j] <- prod[i].bit[j] ^ gbit end end
	 * 
	 * do j = 8 to 14 do k = j-7 to 7 gbit <- (srcA.bit[k] & srcB.bit[j-k])
	 * prod[i].bit[j] <- prod[i].bit[j] ^ gbit end end end
	 * 
	 * do i = 0 to 7 VR[dst].hword[i] <- 0b0 || (prod[2×i] ^ prod[2×i+1]) end
	 */
	Iop_PolynomialMulAdd8x16, Iop_PolynomialMulAdd16x8, Iop_PolynomialMulAdd32x4, Iop_PolynomialMulAdd64x2,

	/* PAIRWISE operations */
	/*
	 * Iop_PwFoo16x4( [a,b,c,d], [e,f,g,h] ) = [Foo16(a,b), Foo16(c,d),
	 * Foo16(e,f), Foo16(g,h)]
	 */
	Iop_PwAdd8x16, Iop_PwAdd16x8, Iop_PwAdd32x4, Iop_PwAdd32Fx2,
	/*
	 * Longening variant is unary. The resulting vector contains two times less
	 * elements than operand, but they are two times wider. Example:
	 * Iop_PwAddL16Ux4( [a,b,c,d] ) = [a+b,c+d] where a+b and c+d are unsigned
	 * 32-bit values.
	 */
	Iop_PwAddL8Ux16, Iop_PwAddL16Ux8, Iop_PwAddL32Ux4, Iop_PwAddL8Sx16, Iop_PwAddL16Sx8, Iop_PwAddL32Sx4,

	/* Other unary pairwise ops */

	/* Vector bit matrix transpose. (V128) -> V128 */
	/*
	 * For each doubleword element of the source vector, an 8-bit x 8-bit matrix
	 * transpose is performed.
	 */
	Iop_PwBitMtxXpose64x2,

	/* ABSOLUTE VALUE */
	Iop_Abs8x16, Iop_Abs16x8, Iop_Abs32x4, Iop_Abs64x2,

	/* AVERAGING: note: (arg1 + arg2 + 1) >>u 1 */
	Iop_Avg8Ux16, Iop_Avg16Ux8, Iop_Avg32Ux4, Iop_Avg8Sx16, Iop_Avg16Sx8, Iop_Avg32Sx4,

	/* MIN/MAX */
	Iop_Max8Sx16, Iop_Max16Sx8, Iop_Max32Sx4, Iop_Max64Sx2, Iop_Max8Ux16, Iop_Max16Ux8, Iop_Max32Ux4, Iop_Max64Ux2, Iop_Min8Sx16, Iop_Min16Sx8, Iop_Min32Sx4, Iop_Min64Sx2, Iop_Min8Ux16, Iop_Min16Ux8, Iop_Min32Ux4, Iop_Min64Ux2,

	/* COMPARISON */
	Iop_CmpEQ8x16, Iop_CmpEQ16x8, Iop_CmpEQ32x4, Iop_CmpEQ64x2, Iop_CmpGT8Sx16, Iop_CmpGT16Sx8, Iop_CmpGT32Sx4, Iop_CmpGT64Sx2, Iop_CmpGT8Ux16, Iop_CmpGT16Ux8, Iop_CmpGT32Ux4, Iop_CmpGT64Ux2,

	/*
	 * COUNT ones / leading zeroes / leading sign bits (not including topmost
	 * bit)
	 */
	Iop_Cnt8x16, Iop_Clz8x16, Iop_Clz16x8, Iop_Clz32x4, Iop_Cls8x16, Iop_Cls16x8, Iop_Cls32x4,

	/* VECTOR x SCALAR SHIFT (shift amt :: Ity_I8) */
	Iop_ShlN8x16, Iop_ShlN16x8, Iop_ShlN32x4, Iop_ShlN64x2, Iop_ShrN8x16, Iop_ShrN16x8, Iop_ShrN32x4, Iop_ShrN64x2, Iop_SarN8x16, Iop_SarN16x8, Iop_SarN32x4, Iop_SarN64x2,

	/* VECTOR x VECTOR SHIFT / ROTATE */
	/*
	 * FIXME: I'm pretty sure the ARM32 front/back ends interpret these
	 * differently from all other targets. The intention is that the shift
	 * amount (2nd arg) is interpreted as unsigned and only the lowest
	 * log2(lane-bits) bits are relevant. But the ARM32 versions treat the shift
	 * amount as an 8 bit signed number. The ARM32 uses should be replaced by
	 * the relevant vector x vector bidirectional shifts instead.
	 */
	Iop_Shl8x16, Iop_Shl16x8, Iop_Shl32x4, Iop_Shl64x2, Iop_Shr8x16, Iop_Shr16x8, Iop_Shr32x4, Iop_Shr64x2, Iop_Sar8x16, Iop_Sar16x8, Iop_Sar32x4, Iop_Sar64x2, Iop_Sal8x16, Iop_Sal16x8, Iop_Sal32x4, Iop_Sal64x2, Iop_Rol8x16, Iop_Rol16x8, Iop_Rol32x4, Iop_Rol64x2,

	/* VECTOR x VECTOR SATURATING SHIFT */
	Iop_QShl8x16, Iop_QShl16x8, Iop_QShl32x4, Iop_QShl64x2, Iop_QSal8x16, Iop_QSal16x8, Iop_QSal32x4, Iop_QSal64x2,
	/* VECTOR x INTEGER SATURATING SHIFT */
	Iop_QShlNsatSU8x16, Iop_QShlNsatSU16x8, Iop_QShlNsatSU32x4, Iop_QShlNsatSU64x2, Iop_QShlNsatUU8x16, Iop_QShlNsatUU16x8, Iop_QShlNsatUU32x4, Iop_QShlNsatUU64x2, Iop_QShlNsatSS8x16, Iop_QShlNsatSS16x8, Iop_QShlNsatSS32x4, Iop_QShlNsatSS64x2,

	/* VECTOR x VECTOR BIDIRECTIONAL SATURATING (& MAYBE ROUNDING) SHIFT */
	/* All of type (V128, V128) -> V256. */
	/*
	 * The least significant 8 bits of each lane of the second operand are used
	 * as the shift amount, and interpreted signedly. Positive values mean a
	 * shift left, negative a shift right. The result is signedly or unsignedly
	 * saturated. There are also rounding variants, which add 2^(shift_amount-1)
	 * to the value before shifting, but only in the shift-right case. Vacated
	 * positions are filled with zeroes. IOW, it's either SHR or SHL, but not
	 * SAR.
	 * 
	 * These operations return 129 bits: one bit ("Q") indicating whether
	 * saturation occurred, and the shift result. The result type is V256, of
	 * which the lower V128 is the shift result, and Q occupies the least
	 * significant bit of the upper V128. All other bits of the upper V128 are
	 * zero.
	 */
	// Unsigned saturation, no rounding
	Iop_QandUQsh8x16, Iop_QandUQsh16x8, Iop_QandUQsh32x4, Iop_QandUQsh64x2,
	// Signed saturation, no rounding
	Iop_QandSQsh8x16, Iop_QandSQsh16x8, Iop_QandSQsh32x4, Iop_QandSQsh64x2,

	// Unsigned saturation, rounding
	Iop_QandUQRsh8x16, Iop_QandUQRsh16x8, Iop_QandUQRsh32x4, Iop_QandUQRsh64x2,
	// Signed saturation, rounding
	Iop_QandSQRsh8x16, Iop_QandSQRsh16x8, Iop_QandSQRsh32x4, Iop_QandSQRsh64x2,

	/* VECTOR x VECTOR BIDIRECTIONAL (& MAYBE ROUNDING) SHIFT */
	/* All of type (V128, V128) -> V128 */
	/*
	 * The least significant 8 bits of each lane of the second operand are used
	 * as the shift amount, and interpreted signedly. Positive values mean a
	 * shift left, negative a shift right. There are also rounding variants,
	 * which add 2^(shift_amount-1) to the value before shifting, but only in
	 * the shift-right case.
	 * 
	 * For left shifts, the vacated places are filled with zeroes. For right
	 * shifts, the vacated places are filled with zeroes for the U variants and
	 * sign bits for the S variants.
	 */
	// Signed and unsigned, non-rounding
	Iop_Sh8Sx16, Iop_Sh16Sx8, Iop_Sh32Sx4, Iop_Sh64Sx2, Iop_Sh8Ux16, Iop_Sh16Ux8, Iop_Sh32Ux4, Iop_Sh64Ux2,

	// Signed and unsigned, rounding
	Iop_Rsh8Sx16, Iop_Rsh16Sx8, Iop_Rsh32Sx4, Iop_Rsh64Sx2, Iop_Rsh8Ux16, Iop_Rsh16Ux8, Iop_Rsh32Ux4, Iop_Rsh64Ux2,

	/*
	 * The least significant 8 bits of each lane of the second operand are used
	 * as the shift amount, and interpreted signedly. Positive values mean a
	 * shift left, negative a shift right. The result is signedly or unsignedly
	 * saturated. There are also rounding variants, which add 2^(shift_amount-1)
	 * to the value before shifting, but only in the shift-right case. Vacated
	 * positions are filled with zeroes. IOW, it's either SHR or SHL, but not
	 * SAR.
	 */

	/*
	 * VECTOR x SCALAR SATURATING (& MAYBE ROUNDING) NARROWING SHIFT RIGHT
	 */
	/* All of type (V128, I8) -> V128 */
	/*
	 * The first argument is shifted right, then narrowed to half the width by
	 * saturating it. The second argument is a scalar shift amount that applies
	 * to all lanes, and must be a value in the range 1 to lane_width. The shift
	 * may be done signedly (Sar variants) or unsignedly (Shr variants). The
	 * saturation is done according to the two signedness indicators at the end
	 * of the name. For example 64Sto32U means a signed 64 bit value is
	 * saturated into an unsigned 32 bit value. Additionally, the QRS variants
	 * do rounding, that is, they add the value (1 << (shift_amount-1)) to each
	 * source lane before shifting.
	 * 
	 * These operations return 65 bits: one bit ("Q") indicating whether
	 * saturation occurred, and the shift result. The result type is V128, of
	 * which the lower half is the shift result, and Q occupies the least
	 * significant bit of the upper half. All other bits of the upper half are
	 * zero.
	 */
	// No rounding, sat U->U
	Iop_QandQShrNnarrow16Uto8Ux8, Iop_QandQShrNnarrow32Uto16Ux4, Iop_QandQShrNnarrow64Uto32Ux2,
	// No rounding, sat S->S
	Iop_QandQSarNnarrow16Sto8Sx8, Iop_QandQSarNnarrow32Sto16Sx4, Iop_QandQSarNnarrow64Sto32Sx2,
	// No rounding, sat S->U
	Iop_QandQSarNnarrow16Sto8Ux8, Iop_QandQSarNnarrow32Sto16Ux4, Iop_QandQSarNnarrow64Sto32Ux2,

	// Rounding, sat U->U
	Iop_QandQRShrNnarrow16Uto8Ux8, Iop_QandQRShrNnarrow32Uto16Ux4, Iop_QandQRShrNnarrow64Uto32Ux2,
	// Rounding, sat S->S
	Iop_QandQRSarNnarrow16Sto8Sx8, Iop_QandQRSarNnarrow32Sto16Sx4, Iop_QandQRSarNnarrow64Sto32Sx2,
	// Rounding, sat S->U
	Iop_QandQRSarNnarrow16Sto8Ux8, Iop_QandQRSarNnarrow32Sto16Ux4, Iop_QandQRSarNnarrow64Sto32Ux2,

	/*
	 * NARROWING (binary) -- narrow 2xV128 into 1xV128, hi half from left arg
	 */
	/* See comments above w.r.t. U vs S issues in saturated narrowing. */
	Iop_QNarrowBin16Sto8Ux16, Iop_QNarrowBin32Sto16Ux8, Iop_QNarrowBin16Sto8Sx16, Iop_QNarrowBin32Sto16Sx8, Iop_QNarrowBin16Uto8Ux16, Iop_QNarrowBin32Uto16Ux8, Iop_NarrowBin16to8x16, Iop_NarrowBin32to16x8, Iop_QNarrowBin64Sto32Sx4, Iop_QNarrowBin64Uto32Ux4, Iop_NarrowBin64to32x4,

	/* NARROWING (unary) -- narrow V128 into I64 */
	Iop_NarrowUn16to8x8, Iop_NarrowUn32to16x4, Iop_NarrowUn64to32x2,
	/*
	 * Saturating narrowing from signed source to signed/unsigned destination
	 */
	Iop_QNarrowUn16Sto8Sx8, Iop_QNarrowUn32Sto16Sx4, Iop_QNarrowUn64Sto32Sx2, Iop_QNarrowUn16Sto8Ux8, Iop_QNarrowUn32Sto16Ux4, Iop_QNarrowUn64Sto32Ux2,
	/* Saturating narrowing from unsigned source to unsigned destination */
	Iop_QNarrowUn16Uto8Ux8, Iop_QNarrowUn32Uto16Ux4, Iop_QNarrowUn64Uto32Ux2,

	/*
	 * WIDENING -- sign or zero extend each element of the argument vector to
	 * the twice original size. The resulting vector consists of the same number
	 * of elements but each element and the vector itself are twice as wide. All
	 * operations are I64->V128. Example Iop_Widen32Sto64x2( [a, b] ) = [c, d]
	 * where c = Iop_32Sto64(a) and d = Iop_32Sto64(b)
	 */
	Iop_Widen8Uto16x8, Iop_Widen16Uto32x4, Iop_Widen32Uto64x2, Iop_Widen8Sto16x8, Iop_Widen16Sto32x4, Iop_Widen32Sto64x2,

	/* INTERLEAVING */
	/*
	 * Interleave lanes from low or high halves of operands. Most-significant
	 * result lane is from the left arg.
	 */
	Iop_InterleaveHI8x16, Iop_InterleaveHI16x8, Iop_InterleaveHI32x4, Iop_InterleaveHI64x2, Iop_InterleaveLO8x16, Iop_InterleaveLO16x8, Iop_InterleaveLO32x4, Iop_InterleaveLO64x2,
	/*
	 * Interleave odd/even lanes of operands. Most-significant result lane is
	 * from the left arg.
	 */
	Iop_InterleaveOddLanes8x16, Iop_InterleaveEvenLanes8x16, Iop_InterleaveOddLanes16x8, Iop_InterleaveEvenLanes16x8, Iop_InterleaveOddLanes32x4, Iop_InterleaveEvenLanes32x4,

	/*
	 * CONCATENATION -- build a new value by concatenating either the even or
	 * odd lanes of both operands. Note that Cat{Odd,Even}Lanes64x2 are
	 * identical to Interleave{HI,LO}64x2 and so are omitted.
	 */
	Iop_CatOddLanes8x16, Iop_CatOddLanes16x8, Iop_CatOddLanes32x4, Iop_CatEvenLanes8x16, Iop_CatEvenLanes16x8, Iop_CatEvenLanes32x4,

	/*
	 * GET elements of VECTOR GET is binop (V128, I8) -> I<elem_size>
	 */
	/* Note: the arm back-end handles only constant second argument. */
	Iop_GetElem8x16, Iop_GetElem16x8, Iop_GetElem32x4, Iop_GetElem64x2,

	/* DUPLICATING -- copy value to all lanes */
	Iop_Dup8x16, Iop_Dup16x8, Iop_Dup32x4,

	/*
	 * SLICE -- produces the lowest 128 bits of (arg1:arg2) >> (8 * arg3). arg3
	 * is a shift amount in bytes and may be between 0 and 16 inclusive. When 0,
	 * the result is arg2; when 16, the result is arg1. Not all back ends handle
	 * all values. The arm64 back end handles only immediate arg3 values.
	 */
	Iop_SliceV128, // (V128, V128, I8) -> V128

	/*
	 * REVERSE the order of chunks in vector lanes. Chunks must be smaller than
	 * the vector lanes (obviously) and so may be 8-, 16- and 32-bit in size.
	 * See definitions of 64-bit SIMD versions above for examples.
	 */
	Iop_Reverse8sIn16_x8, Iop_Reverse8sIn32_x4, Iop_Reverse16sIn32_x4, Iop_Reverse8sIn64_x2, Iop_Reverse16sIn64_x2, Iop_Reverse32sIn64_x2, Iop_Reverse1sIn8_x16, /*
																																									 * Reverse
																																									 * bits
																																									 * in
																																									 * each
																																									 * byte
																																									 * lane.
																																									 */

	/*
	 * PERMUTING -- copy src bytes to dst, as indexed by control vector bytes:
	 * for i in 0 .. 15 . result[i] = argL[ argR[i] ] argR[i] values may only be
	 * in the range 0 .. 15, else behaviour is undefined.
	 */
	Iop_Perm8x16, Iop_Perm32x4, /*
								 * ditto, except argR values are restricted to 0
								 * .. 3
								 */

	/*
	 * MISC CONVERSION -- get high bits of each byte lane, a la x86/amd64
	 * pmovmskb
	 */
	Iop_GetMSBs8x16, /* V128 -> I16 */

	/*
	 * Vector Reciprocal Estimate and Vector Reciprocal Square Root Estimate See
	 * floating-point equivalents for details.
	 */
	Iop_RecipEst32Ux4, Iop_RSqrtEst32Ux4,

	/* ------------------ 256-bit SIMD Integer. ------------------ */

	/* Pack/unpack */
	Iop_V256to64_0, // V256 -> I64, extract least significant lane
	Iop_V256to64_1, Iop_V256to64_2, Iop_V256to64_3, // V256 -> I64, extract
													// most significant lane

	Iop_64x4toV256, // (I64,I64,I64,I64)->V256
					// first arg is most significant lane

	Iop_V256toV128_0, // V256 -> V128, less significant lane
	Iop_V256toV128_1, // V256 -> V128, more significant lane
	Iop_V128HLtoV256, // (V128,V128)->V256, first arg is most signif

	Iop_AndV256, Iop_OrV256, Iop_XorV256, Iop_NotV256,

	/* MISC (vector integer cmp != 0) */
	Iop_CmpNEZ8x32, Iop_CmpNEZ16x16, Iop_CmpNEZ32x8, Iop_CmpNEZ64x4,

	Iop_Add8x32, Iop_Add16x16, Iop_Add32x8, Iop_Add64x4, Iop_Sub8x32, Iop_Sub16x16, Iop_Sub32x8, Iop_Sub64x4,

	Iop_CmpEQ8x32, Iop_CmpEQ16x16, Iop_CmpEQ32x8, Iop_CmpEQ64x4, Iop_CmpGT8Sx32, Iop_CmpGT16Sx16, Iop_CmpGT32Sx8, Iop_CmpGT64Sx4,

	Iop_ShlN16x16, Iop_ShlN32x8, Iop_ShlN64x4, Iop_ShrN16x16, Iop_ShrN32x8, Iop_ShrN64x4, Iop_SarN16x16, Iop_SarN32x8,

	Iop_Max8Sx32, Iop_Max16Sx16, Iop_Max32Sx8, Iop_Max8Ux32, Iop_Max16Ux16, Iop_Max32Ux8, Iop_Min8Sx32, Iop_Min16Sx16, Iop_Min32Sx8, Iop_Min8Ux32, Iop_Min16Ux16, Iop_Min32Ux8,

	Iop_Mul16x16, Iop_Mul32x8, Iop_MulHi16Ux16, Iop_MulHi16Sx16,

	Iop_QAdd8Ux32, Iop_QAdd16Ux16, Iop_QAdd8Sx32, Iop_QAdd16Sx16, Iop_QSub8Ux32, Iop_QSub16Ux16, Iop_QSub8Sx32, Iop_QSub16Sx16,

	Iop_Avg8Ux32, Iop_Avg16Ux16,

	Iop_Perm32x8,

	/* (V128, V128) -> V128 */
	Iop_CipherV128, Iop_CipherLV128, Iop_CipherSV128, Iop_NCipherV128, Iop_NCipherLV128,

	/*
	 * Hash instructions, Federal Information Processing Standards Publication
	 * 180-3 Secure Hash Standard.
	 */
	/*
	 * (V128, I8) -> V128; The I8 input arg is (ST | SIX), where ST and SIX are
	 * fields from the insn. See ISA 2.07 description of vshasigmad and
	 * vshasigmaw insns.
	 */
	Iop_SHA512, Iop_SHA256,

	/* ------------------ 256-bit SIMD FP. ------------------ */

	/* ternary :: IRRoundingMode(I32) x V256 x V256 -> V256 */
	Iop_Add64Fx4, Iop_Sub64Fx4, Iop_Mul64Fx4, Iop_Div64Fx4, Iop_Add32Fx8, Iop_Sub32Fx8, Iop_Mul32Fx8, Iop_Div32Fx8,

	Iop_Sqrt32Fx8, Iop_Sqrt64Fx4, Iop_RSqrtEst32Fx8, Iop_RecipEst32Fx8,

	Iop_Max32Fx8, Iop_Min32Fx8, Iop_Max64Fx4, Iop_Min64Fx4, Iop_LAST /*
																		 * must
																		 * be
																		 * the
																		 * last
																		 * enumerator
																		 */
	;

	@JsonIgnore
	public static int startValue() {
		return 0x1400;
	}

	@JsonIgnore
	public static VexOperationType fromInteger(int index) {
		return VexEnumeration.retrieveType(index, VexOperationType.class);
	}

	@JsonIgnore
	public Attribute att() {
		return VexOperationUtils.attr(this);
	}

	@JsonIgnore
	public TypeInformation getTypeInfo() {
		return VexOperationUtils.typeOfPrimop(this);
	}

	public static void main(String[] args) {
		String vals = StringResources.JOINER_TOKEN_CSV_SPACE.join(
				Arrays.stream(VexOperationType.values()).map(val -> "\"" + val + "\"").collect(Collectors.toList()));

		System.out.println(vals);
	}

}