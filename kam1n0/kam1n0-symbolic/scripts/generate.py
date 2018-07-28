#!/usr/bin/python env
"""
This module contains symbolic implementations of VEX operations.
"""

import re
import sys
import collections
import itertools
import operator

import logging
l = logging.getLogger("simuvex.vex.irop.generate")

import json
from json import JSONEncoder

#
# The more sane approach
#

def op_attrs(p):
    m = re.match(r'^Iop_' \
              r'(?P<generic_name>\D+?)??' \
              r'(?P<from_type>I|F|D|V)??' \
              r'(?P<from_signed>U|S)??' \
              r'(?P<from_size>\d+)??' \
              r'(?P<from_signed_back>U|S)??' \
              # this screws up CmpLE: r'(?P<e_flag>E)??' \
              r'('
                r'(?P<from_side>HL|HI|L|LO)??' \
                r'(?P<conversion>to|as)' \
                r'(?P<to_type>Int|I|F|D|V)??' \
                r'(?P<to_size>\d+)??' \
                r'(?P<to_signed>U|S)??' \
              r')??'
              r'(?P<vector_info>\d+U?S?F?0?x\d+)??' \
              r'(?P<rounding_mode>_R(Z|P|N|M))?$', \
              p)

    if not m:
        print "Unmatched operation: %s" % p
        return None
    else:
        l.debug("Matched operation: %s", p)
        attrs = m.groupdict()

        attrs['from_signed'] = attrs['from_signed_back'] if attrs['from_signed'] is None else attrs['from_signed']
        attrs.pop('from_signed_back', None)
        if attrs['generic_name'] == 'CmpOR':
            assert attrs['from_type'] == 'D'
            attrs['generic_name'] = 'CmpORD'
            attrs['from_type'] = None

        # fix up vector stuff
        vector_info = attrs.pop('vector_info', None)
        if vector_info:
            vm = re.match(r'^(?P<vector_size>\d+)?' \
                 r'(?P<vector_signed>U|S)?' \
                 r'(?P<vector_type>F|D)?' \
                 r'(?P<vector_zero>0)?' \
     r'x' \
                 r'(?P<vector_count>\d+)?$', \
                 vector_info)
            attrs.update(vm.groupdict())

        for k,v in attrs.items():
            if v is not None and v != "":
                l.debug("... %s: %s", k, v)

        return attrs

all_operations = ["Iop_INVALID", "Iop_Add8", "Iop_Add16", "Iop_Add32", "Iop_Add64", "Iop_Sub8", "Iop_Sub16", "Iop_Sub32", "Iop_Sub64", "Iop_Mul8", "Iop_Mul16", "Iop_Mul32", "Iop_Mul64", "Iop_Or8", "Iop_Or16", "Iop_Or32", "Iop_Or64", "Iop_And8", "Iop_And16", "Iop_And32", "Iop_And64", "Iop_Xor8", "Iop_Xor16", "Iop_Xor32", "Iop_Xor64", "Iop_Shl8", "Iop_Shl16", "Iop_Shl32", "Iop_Shl64", "Iop_Shr8", "Iop_Shr16", "Iop_Shr32", "Iop_Shr64", "Iop_Sar8", "Iop_Sar16", "Iop_Sar32", "Iop_Sar64", "Iop_CmpEQ8", "Iop_CmpEQ16", "Iop_CmpEQ32", "Iop_CmpEQ64", "Iop_CmpNE8", "Iop_CmpNE16", "Iop_CmpNE32", "Iop_CmpNE64", "Iop_Not8", "Iop_Not16", "Iop_Not32", "Iop_Not64", "Iop_CasCmpEQ8", "Iop_CasCmpEQ16", "Iop_CasCmpEQ32", "Iop_CasCmpEQ64", "Iop_CasCmpNE8", "Iop_CasCmpNE16", "Iop_CasCmpNE32", "Iop_CasCmpNE64", "Iop_ExpCmpNE8", "Iop_ExpCmpNE16", "Iop_ExpCmpNE32", "Iop_ExpCmpNE64", "Iop_MullS8", "Iop_MullS16", "Iop_MullS32", "Iop_MullS64", "Iop_MullU8", "Iop_MullU16", "Iop_MullU32", "Iop_MullU64", "Iop_Clz64", "Iop_Clz32", "Iop_Ctz64", "Iop_Ctz32", "Iop_CmpLT32S", "Iop_CmpLT64S", "Iop_CmpLE32S", "Iop_CmpLE64S", "Iop_CmpLT32U", "Iop_CmpLT64U", "Iop_CmpLE32U", "Iop_CmpLE64U", "Iop_CmpNEZ8", "Iop_CmpNEZ16", "Iop_CmpNEZ32", "Iop_CmpNEZ64", "Iop_CmpwNEZ32", "Iop_CmpwNEZ64", "Iop_Left8", "Iop_Left16", "Iop_Left32", "Iop_Left64", "Iop_Max32U", "Iop_CmpORD32U", "Iop_CmpORD64U", "Iop_CmpORD32S", "Iop_CmpORD64S", "Iop_DivU32", "Iop_DivS32", "Iop_DivU64", "Iop_DivS64", "Iop_DivU64E", "Iop_DivS64E", "Iop_DivU32E", "Iop_DivS32E", "Iop_DivModU64to32", "Iop_DivModS64to32", "Iop_DivModU128to64", "Iop_DivModS128to64", "Iop_DivModS64to64", "Iop_8Uto16", "Iop_8Uto32", "Iop_8Uto64", "Iop_16Uto32", "Iop_16Uto64", "Iop_32Uto64", "Iop_8Sto16", "Iop_8Sto32", "Iop_8Sto64", "Iop_16Sto32", "Iop_16Sto64", "Iop_32Sto64", "Iop_64to8", "Iop_32to8", "Iop_64to16", "Iop_16to8", "Iop_16HIto8", "Iop_8HLto16", "Iop_32to16", "Iop_32HIto16", "Iop_16HLto32", "Iop_64to32", "Iop_64HIto32", "Iop_32HLto64", "Iop_128to64", "Iop_128HIto64", "Iop_64HLto128", "Iop_Not1", "Iop_32to1", "Iop_64to1", "Iop_1Uto8", "Iop_1Uto32", "Iop_1Uto64", "Iop_1Sto8", "Iop_1Sto16", "Iop_1Sto32", "Iop_1Sto64", "Iop_AddF64", "Iop_SubF64", "Iop_MulF64", "Iop_DivF64", "Iop_AddF32", "Iop_SubF32", "Iop_MulF32", "Iop_DivF32", "Iop_AddF64r32", "Iop_SubF64r32", "Iop_MulF64r32", "Iop_DivF64r32", "Iop_NegF64", "Iop_AbsF64", "Iop_NegF32", "Iop_AbsF32", "Iop_SqrtF64", "Iop_SqrtF32", "Iop_CmpF64", "Iop_CmpF32", "Iop_CmpF128", "Iop_F64toI16S", "Iop_F64toI32S", "Iop_F64toI64S", "Iop_F64toI64U", "Iop_F64toI32U", "Iop_I32StoF64", "Iop_I64StoF64", "Iop_I64UtoF64", "Iop_I64UtoF32", "Iop_I32UtoF32", "Iop_I32UtoF64", "Iop_F32toI32S", "Iop_F32toI64S", "Iop_F32toI32U", "Iop_F32toI64U", "Iop_I32StoF32", "Iop_I64StoF32", "Iop_F32toF64", "Iop_F64toF32", "Iop_ReinterpF64asI64", "Iop_ReinterpI64asF64", "Iop_ReinterpF32asI32", "Iop_ReinterpI32asF32", "Iop_F64HLtoF128", "Iop_F128HItoF64", "Iop_F128LOtoF64", "Iop_AddF128", "Iop_SubF128", "Iop_MulF128", "Iop_DivF128", "Iop_NegF128", "Iop_AbsF128", "Iop_SqrtF128", "Iop_I32StoF128", "Iop_I64StoF128", "Iop_I32UtoF128", "Iop_I64UtoF128", "Iop_F32toF128", "Iop_F64toF128", "Iop_F128toI32S", "Iop_F128toI64S", "Iop_F128toI32U", "Iop_F128toI64U", "Iop_F128toF64", "Iop_F128toF32", "Iop_AtanF64", "Iop_Yl2xF64", "Iop_Yl2xp1F64", "Iop_PRemF64", "Iop_PRemC3210F64", "Iop_PRem1F64", "Iop_PRem1C3210F64", "Iop_ScaleF64", "Iop_SinF64", "Iop_CosF64", "Iop_TanF64", "Iop_2xm1F64", "Iop_RoundF64toInt", "Iop_RoundF32toInt", "Iop_MAddF32", "Iop_MSubF32", "Iop_MAddF64", "Iop_MSubF64", "Iop_MAddF64r32", "Iop_MSubF64r32", "Iop_RSqrtEst5GoodF64", "Iop_RoundF64toF64_NEAREST", "Iop_RoundF64toF64_NegINF", "Iop_RoundF64toF64_PosINF", "Iop_RoundF64toF64_ZERO", "Iop_TruncF64asF32", "Iop_RoundF64toF32", "Iop_RecpExpF64", "Iop_RecpExpF32", "Iop_F16toF64", "Iop_F64toF16", "Iop_F16toF32", "Iop_F32toF16", "Iop_QAdd32S", "Iop_QSub32S", "Iop_Add16x2", "Iop_Sub16x2", "Iop_QAdd16Sx2", "Iop_QAdd16Ux2", "Iop_QSub16Sx2", "Iop_QSub16Ux2", "Iop_HAdd16Ux2", "Iop_HAdd16Sx2", "Iop_HSub16Ux2", "Iop_HSub16Sx2", "Iop_Add8x4", "Iop_Sub8x4", "Iop_QAdd8Sx4", "Iop_QAdd8Ux4", "Iop_QSub8Sx4", "Iop_QSub8Ux4", "Iop_HAdd8Ux4", "Iop_HAdd8Sx4", "Iop_HSub8Ux4", "Iop_HSub8Sx4", "Iop_Sad8Ux4", "Iop_CmpNEZ16x2", "Iop_CmpNEZ8x4", "Iop_I32UtoFx2", "Iop_I32StoFx2", "Iop_FtoI32Ux2_RZ", "Iop_FtoI32Sx2_RZ", "Iop_F32ToFixed32Ux2_RZ", "Iop_F32ToFixed32Sx2_RZ", "Iop_Fixed32UToF32x2_RN", "Iop_Fixed32SToF32x2_RN", "Iop_Max32Fx2", "Iop_Min32Fx2", "Iop_PwMax32Fx2", "Iop_PwMin32Fx2", "Iop_CmpEQ32Fx2", "Iop_CmpGT32Fx2", "Iop_CmpGE32Fx2", "Iop_RecipEst32Fx2", "Iop_RecipStep32Fx2", "Iop_RSqrtEst32Fx2", "Iop_RSqrtStep32Fx2", "Iop_Neg32Fx2", "Iop_Abs32Fx2", "Iop_CmpNEZ8x8", "Iop_CmpNEZ16x4", "Iop_CmpNEZ32x2", "Iop_Add8x8", "Iop_Add16x4", "Iop_Add32x2", "Iop_QAdd8Ux8", "Iop_QAdd16Ux4", "Iop_QAdd32Ux2", "Iop_QAdd64Ux1", "Iop_QAdd8Sx8", "Iop_QAdd16Sx4", "Iop_QAdd32Sx2", "Iop_QAdd64Sx1", "Iop_PwAdd8x8", "Iop_PwAdd16x4", "Iop_PwAdd32x2", "Iop_PwMax8Sx8", "Iop_PwMax16Sx4", "Iop_PwMax32Sx2", "Iop_PwMax8Ux8", "Iop_PwMax16Ux4", "Iop_PwMax32Ux2", "Iop_PwMin8Sx8", "Iop_PwMin16Sx4", "Iop_PwMin32Sx2", "Iop_PwMin8Ux8", "Iop_PwMin16Ux4", "Iop_PwMin32Ux2", "Iop_PwAddL8Ux8", "Iop_PwAddL16Ux4", "Iop_PwAddL32Ux2", "Iop_PwAddL8Sx8", "Iop_PwAddL16Sx4", "Iop_PwAddL32Sx2", "Iop_Sub8x8", "Iop_Sub16x4", "Iop_Sub32x2", "Iop_QSub8Ux8", "Iop_QSub16Ux4", "Iop_QSub32Ux2", "Iop_QSub64Ux1", "Iop_QSub8Sx8", "Iop_QSub16Sx4", "Iop_QSub32Sx2", "Iop_QSub64Sx1", "Iop_Abs8x8", "Iop_Abs16x4", "Iop_Abs32x2", "Iop_Mul8x8", "Iop_Mul16x4", "Iop_Mul32x2", "Iop_Mul32Fx2", "Iop_MulHi16Ux4", "Iop_MulHi16Sx4", "Iop_PolynomialMul8x8", "Iop_QDMulHi16Sx4", "Iop_QDMulHi32Sx2", "Iop_QRDMulHi16Sx4", "Iop_QRDMulHi32Sx2", "Iop_Avg8Ux8", "Iop_Avg16Ux4", "Iop_Max8Sx8", "Iop_Max16Sx4", "Iop_Max32Sx2", "Iop_Max8Ux8", "Iop_Max16Ux4", "Iop_Max32Ux2", "Iop_Min8Sx8", "Iop_Min16Sx4", "Iop_Min32Sx2", "Iop_Min8Ux8", "Iop_Min16Ux4", "Iop_Min32Ux2", "Iop_CmpEQ8x8", "Iop_CmpEQ16x4", "Iop_CmpEQ32x2", "Iop_CmpGT8Ux8", "Iop_CmpGT16Ux4", "Iop_CmpGT32Ux2", "Iop_CmpGT8Sx8", "Iop_CmpGT16Sx4", "Iop_CmpGT32Sx2", "Iop_Cnt8x8", "Iop_Clz8x8", "Iop_Clz16x4", "Iop_Clz32x2", "Iop_Cls8x8", "Iop_Cls16x4", "Iop_Cls32x2", "Iop_Clz64x2", "Iop_Shl8x8", "Iop_Shl16x4", "Iop_Shl32x2", "Iop_Shr8x8", "Iop_Shr16x4", "Iop_Shr32x2", "Iop_Sar8x8", "Iop_Sar16x4", "Iop_Sar32x2", "Iop_Sal8x8", "Iop_Sal16x4", "Iop_Sal32x2", "Iop_Sal64x1", "Iop_ShlN8x8", "Iop_ShlN16x4", "Iop_ShlN32x2", "Iop_ShrN8x8", "Iop_ShrN16x4", "Iop_ShrN32x2", "Iop_SarN8x8", "Iop_SarN16x4", "Iop_SarN32x2", "Iop_QShl8x8", "Iop_QShl16x4", "Iop_QShl32x2", "Iop_QShl64x1", "Iop_QSal8x8", "Iop_QSal16x4", "Iop_QSal32x2", "Iop_QSal64x1", "Iop_QShlNsatSU8x8", "Iop_QShlNsatSU16x4", "Iop_QShlNsatSU32x2", "Iop_QShlNsatSU64x1", "Iop_QShlNsatUU8x8", "Iop_QShlNsatUU16x4", "Iop_QShlNsatUU32x2", "Iop_QShlNsatUU64x1", "Iop_QShlNsatSS8x8", "Iop_QShlNsatSS16x4", "Iop_QShlNsatSS32x2", "Iop_QShlNsatSS64x1", "Iop_QNarrowBin16Sto8Ux8", "Iop_QNarrowBin16Sto8Sx8", "Iop_QNarrowBin32Sto16Sx4", "Iop_NarrowBin16to8x8", "Iop_NarrowBin32to16x4", "Iop_InterleaveHI8x8", "Iop_InterleaveHI16x4", "Iop_InterleaveHI32x2", "Iop_InterleaveLO8x8", "Iop_InterleaveLO16x4", "Iop_InterleaveLO32x2", "Iop_InterleaveOddLanes8x8", "Iop_InterleaveEvenLanes8x8", "Iop_InterleaveOddLanes16x4", "Iop_InterleaveEvenLanes16x4", "Iop_CatOddLanes8x8", "Iop_CatOddLanes16x4", "Iop_CatEvenLanes8x8", "Iop_CatEvenLanes16x4", "Iop_GetElem8x8", "Iop_GetElem16x4", "Iop_GetElem32x2", "Iop_SetElem8x8", "Iop_SetElem16x4", "Iop_SetElem32x2", "Iop_Dup8x8", "Iop_Dup16x4", "Iop_Dup32x2", "Iop_Slice64", "Iop_Reverse8sIn16_x4", "Iop_Reverse8sIn32_x2", "Iop_Reverse16sIn32_x2", "Iop_Reverse8sIn64_x1", "Iop_Reverse16sIn64_x1", "Iop_Reverse32sIn64_x1", "Iop_Perm8x8", "Iop_GetMSBs8x8", "Iop_RecipEst32Ux2", "Iop_RSqrtEst32Ux2", "Iop_AddD64", "Iop_SubD64", "Iop_MulD64", "Iop_DivD64", "Iop_AddD128", "Iop_SubD128", "Iop_MulD128", "Iop_DivD128", "Iop_ShlD64", "Iop_ShrD64", "Iop_ShlD128", "Iop_ShrD128", "Iop_D32toD64", "Iop_D64toD128", "Iop_I32StoD128", "Iop_I32UtoD128", "Iop_I64StoD128", "Iop_I64UtoD128", "Iop_D64toD32", "Iop_D128toD64", "Iop_I32StoD64", "Iop_I32UtoD64", "Iop_I64StoD64", "Iop_I64UtoD64", "Iop_D64toI32S", "Iop_D64toI32U", "Iop_D64toI64S", "Iop_D64toI64U", "Iop_D128toI32S", "Iop_D128toI32U", "Iop_D128toI64S", "Iop_D128toI64U", "Iop_F32toD32", "Iop_F32toD64", "Iop_F32toD128", "Iop_F64toD32", "Iop_F64toD64", "Iop_F64toD128", "Iop_F128toD32", "Iop_F128toD64", "Iop_F128toD128", "Iop_D32toF32", "Iop_D32toF64", "Iop_D32toF128", "Iop_D64toF32", "Iop_D64toF64", "Iop_D64toF128", "Iop_D128toF32", "Iop_D128toF64", "Iop_D128toF128", "Iop_RoundD64toInt", "Iop_RoundD128toInt", "Iop_CmpD64", "Iop_CmpD128", "Iop_CmpExpD64", "Iop_CmpExpD128", "Iop_QuantizeD64", "Iop_QuantizeD128", "Iop_SignificanceRoundD64", "Iop_SignificanceRoundD128", "Iop_ExtractExpD64", "Iop_ExtractExpD128", "Iop_ExtractSigD64", "Iop_ExtractSigD128", "Iop_InsertExpD64", "Iop_InsertExpD128", "Iop_D64HLtoD128", "Iop_D128HItoD64", "Iop_D128LOtoD64", "Iop_DPBtoBCD", "Iop_BCDtoDPB", "Iop_BCDAdd", "Iop_BCDSub", "Iop_ReinterpI64asD64", "Iop_ReinterpD64asI64", "Iop_Add32Fx4", "Iop_Sub32Fx4", "Iop_Mul32Fx4", "Iop_Div32Fx4", "Iop_Max32Fx4", "Iop_Min32Fx4", "Iop_Add32Fx2", "Iop_Sub32Fx2", "Iop_CmpEQ32Fx4", "Iop_CmpLT32Fx4", "Iop_CmpLE32Fx4", "Iop_CmpUN32Fx4", "Iop_CmpGT32Fx4", "Iop_CmpGE32Fx4", "Iop_PwMax32Fx4", "Iop_PwMin32Fx4", "Iop_Abs32Fx4", "Iop_Neg32Fx4", "Iop_Sqrt32Fx4", "Iop_RecipEst32Fx4", "Iop_RecipStep32Fx4", "Iop_RSqrtEst32Fx4", "Iop_RSqrtStep32Fx4", "Iop_I32UtoFx4", "Iop_I32StoFx4", "Iop_FtoI32Ux4_RZ", "Iop_FtoI32Sx4_RZ", "Iop_QFtoI32Ux4_RZ", "Iop_QFtoI32Sx4_RZ", "Iop_RoundF32x4_RM", "Iop_RoundF32x4_RP", "Iop_RoundF32x4_RN", "Iop_RoundF32x4_RZ", "Iop_F32ToFixed32Ux4_RZ", "Iop_F32ToFixed32Sx4_RZ", "Iop_Fixed32UToF32x4_RN", "Iop_Fixed32SToF32x4_RN", "Iop_F32toF16x4", "Iop_F16toF32x4", "Iop_Add32F0x4", "Iop_Sub32F0x4", "Iop_Mul32F0x4", "Iop_Div32F0x4", "Iop_Max32F0x4", "Iop_Min32F0x4", "Iop_CmpEQ32F0x4", "Iop_CmpLT32F0x4", "Iop_CmpLE32F0x4", "Iop_CmpUN32F0x4", "Iop_RecipEst32F0x4", "Iop_Sqrt32F0x4", "Iop_RSqrtEst32F0x4", "Iop_Add64Fx2", "Iop_Sub64Fx2", "Iop_Mul64Fx2", "Iop_Div64Fx2", "Iop_Max64Fx2", "Iop_Min64Fx2", "Iop_CmpEQ64Fx2", "Iop_CmpLT64Fx2", "Iop_CmpLE64Fx2", "Iop_CmpUN64Fx2", "Iop_Abs64Fx2", "Iop_Neg64Fx2", "Iop_Sqrt64Fx2", "Iop_RecipEst64Fx2", "Iop_RecipStep64Fx2", "Iop_RSqrtEst64Fx2", "Iop_RSqrtStep64Fx2", "Iop_Add64F0x2", "Iop_Sub64F0x2", "Iop_Mul64F0x2", "Iop_Div64F0x2", "Iop_Max64F0x2", "Iop_Min64F0x2", "Iop_CmpEQ64F0x2", "Iop_CmpLT64F0x2", "Iop_CmpLE64F0x2", "Iop_CmpUN64F0x2", "Iop_Sqrt64F0x2", "Iop_V128to64", "Iop_V128HIto64", "Iop_64HLtoV128", "Iop_64UtoV128", "Iop_SetV128lo64", "Iop_ZeroHI64ofV128", "Iop_ZeroHI96ofV128", "Iop_ZeroHI112ofV128", "Iop_ZeroHI120ofV128", "Iop_32UtoV128", "Iop_V128to32", "Iop_SetV128lo32", "Iop_NotV128", "Iop_AndV128", "Iop_OrV128", "Iop_XorV128", "Iop_ShlV128", "Iop_ShrV128", "Iop_CmpNEZ8x16", "Iop_CmpNEZ16x8", "Iop_CmpNEZ32x4", "Iop_CmpNEZ64x2", "Iop_Add8x16", "Iop_Add16x8", "Iop_Add32x4", "Iop_Add64x2", "Iop_QAdd8Ux16", "Iop_QAdd16Ux8", "Iop_QAdd32Ux4", "Iop_QAdd64Ux2", "Iop_QAdd8Sx16", "Iop_QAdd16Sx8", "Iop_QAdd32Sx4", "Iop_QAdd64Sx2", "Iop_QAddExtUSsatSS8x16", "Iop_QAddExtUSsatSS16x8", "Iop_QAddExtUSsatSS32x4", "Iop_QAddExtUSsatSS64x2", "Iop_QAddExtSUsatUU8x16", "Iop_QAddExtSUsatUU16x8", "Iop_QAddExtSUsatUU32x4", "Iop_QAddExtSUsatUU64x2", "Iop_Sub8x16", "Iop_Sub16x8", "Iop_Sub32x4", "Iop_Sub64x2", "Iop_QSub8Ux16", "Iop_QSub16Ux8", "Iop_QSub32Ux4", "Iop_QSub64Ux2", "Iop_QSub8Sx16", "Iop_QSub16Sx8", "Iop_QSub32Sx4", "Iop_QSub64Sx2", "Iop_Mul8x16", "Iop_Mul16x8", "Iop_Mul32x4", "Iop_MulHi16Ux8", "Iop_MulHi32Ux4", "Iop_MulHi16Sx8", "Iop_MulHi32Sx4", "Iop_MullEven8Ux16", "Iop_MullEven16Ux8", "Iop_MullEven32Ux4", "Iop_MullEven8Sx16", "Iop_MullEven16Sx8", "Iop_MullEven32Sx4", "Iop_Mull8Ux8", "Iop_Mull8Sx8", "Iop_Mull16Ux4", "Iop_Mull16Sx4", "Iop_Mull32Ux2", "Iop_Mull32Sx2", "Iop_QDMull16Sx4", "Iop_QDMull32Sx2", "Iop_QDMulHi16Sx8", "Iop_QDMulHi32Sx4", "Iop_QRDMulHi16Sx8", "Iop_QRDMulHi32Sx4", "Iop_PolynomialMul8x16", "Iop_PolynomialMull8x8", "Iop_PolynomialMulAdd8x16", "Iop_PolynomialMulAdd16x8", "Iop_PolynomialMulAdd32x4", "Iop_PolynomialMulAdd64x2", "Iop_PwAdd8x16", "Iop_PwAdd16x8", "Iop_PwAdd32x4", "Iop_PwAdd32Fx2", "Iop_PwAddL8Ux16", "Iop_PwAddL16Ux8", "Iop_PwAddL32Ux4", "Iop_PwAddL8Sx16", "Iop_PwAddL16Sx8", "Iop_PwAddL32Sx4", "Iop_PwBitMtxXpose64x2", "Iop_Abs8x16", "Iop_Abs16x8", "Iop_Abs32x4", "Iop_Abs64x2", "Iop_Avg8Ux16", "Iop_Avg16Ux8", "Iop_Avg32Ux4", "Iop_Avg8Sx16", "Iop_Avg16Sx8", "Iop_Avg32Sx4", "Iop_Max8Sx16", "Iop_Max16Sx8", "Iop_Max32Sx4", "Iop_Max64Sx2", "Iop_Max8Ux16", "Iop_Max16Ux8", "Iop_Max32Ux4", "Iop_Max64Ux2", "Iop_Min8Sx16", "Iop_Min16Sx8", "Iop_Min32Sx4", "Iop_Min64Sx2", "Iop_Min8Ux16", "Iop_Min16Ux8", "Iop_Min32Ux4", "Iop_Min64Ux2", "Iop_CmpEQ8x16", "Iop_CmpEQ16x8", "Iop_CmpEQ32x4", "Iop_CmpEQ64x2", "Iop_CmpGT8Sx16", "Iop_CmpGT16Sx8", "Iop_CmpGT32Sx4", "Iop_CmpGT64Sx2", "Iop_CmpGT8Ux16", "Iop_CmpGT16Ux8", "Iop_CmpGT32Ux4", "Iop_CmpGT64Ux2", "Iop_Cnt8x16", "Iop_Clz8x16", "Iop_Clz16x8", "Iop_Clz32x4", "Iop_Cls8x16", "Iop_Cls16x8", "Iop_Cls32x4", "Iop_ShlN8x16", "Iop_ShlN16x8", "Iop_ShlN32x4", "Iop_ShlN64x2", "Iop_ShrN8x16", "Iop_ShrN16x8", "Iop_ShrN32x4", "Iop_ShrN64x2", "Iop_SarN8x16", "Iop_SarN16x8", "Iop_SarN32x4", "Iop_SarN64x2", "Iop_Shl8x16", "Iop_Shl16x8", "Iop_Shl32x4", "Iop_Shl64x2", "Iop_Shr8x16", "Iop_Shr16x8", "Iop_Shr32x4", "Iop_Shr64x2", "Iop_Sar8x16", "Iop_Sar16x8", "Iop_Sar32x4", "Iop_Sar64x2", "Iop_Sal8x16", "Iop_Sal16x8", "Iop_Sal32x4", "Iop_Sal64x2", "Iop_Rol8x16", "Iop_Rol16x8", "Iop_Rol32x4", "Iop_Rol64x2", "Iop_QShl8x16", "Iop_QShl16x8", "Iop_QShl32x4", "Iop_QShl64x2", "Iop_QSal8x16", "Iop_QSal16x8", "Iop_QSal32x4", "Iop_QSal64x2", "Iop_QShlNsatSU8x16", "Iop_QShlNsatSU16x8", "Iop_QShlNsatSU32x4", "Iop_QShlNsatSU64x2", "Iop_QShlNsatUU8x16", "Iop_QShlNsatUU16x8", "Iop_QShlNsatUU32x4", "Iop_QShlNsatUU64x2", "Iop_QShlNsatSS8x16", "Iop_QShlNsatSS16x8", "Iop_QShlNsatSS32x4", "Iop_QShlNsatSS64x2", "Iop_QandUQsh8x16", "Iop_QandUQsh16x8", "Iop_QandUQsh32x4", "Iop_QandUQsh64x2", "Iop_QandSQsh8x16", "Iop_QandSQsh16x8", "Iop_QandSQsh32x4", "Iop_QandSQsh64x2", "Iop_QandUQRsh8x16", "Iop_QandUQRsh16x8", "Iop_QandUQRsh32x4", "Iop_QandUQRsh64x2", "Iop_QandSQRsh8x16", "Iop_QandSQRsh16x8", "Iop_QandSQRsh32x4", "Iop_QandSQRsh64x2", "Iop_Sh8Sx16", "Iop_Sh16Sx8", "Iop_Sh32Sx4", "Iop_Sh64Sx2", "Iop_Sh8Ux16", "Iop_Sh16Ux8", "Iop_Sh32Ux4", "Iop_Sh64Ux2", "Iop_Rsh8Sx16", "Iop_Rsh16Sx8", "Iop_Rsh32Sx4", "Iop_Rsh64Sx2", "Iop_Rsh8Ux16", "Iop_Rsh16Ux8", "Iop_Rsh32Ux4", "Iop_Rsh64Ux2", "Iop_QandQShrNnarrow16Uto8Ux8", "Iop_QandQShrNnarrow32Uto16Ux4", "Iop_QandQShrNnarrow64Uto32Ux2", "Iop_QandQSarNnarrow16Sto8Sx8", "Iop_QandQSarNnarrow32Sto16Sx4", "Iop_QandQSarNnarrow64Sto32Sx2", "Iop_QandQSarNnarrow16Sto8Ux8", "Iop_QandQSarNnarrow32Sto16Ux4", "Iop_QandQSarNnarrow64Sto32Ux2", "Iop_QandQRShrNnarrow16Uto8Ux8", "Iop_QandQRShrNnarrow32Uto16Ux4", "Iop_QandQRShrNnarrow64Uto32Ux2", "Iop_QandQRSarNnarrow16Sto8Sx8", "Iop_QandQRSarNnarrow32Sto16Sx4", "Iop_QandQRSarNnarrow64Sto32Sx2", "Iop_QandQRSarNnarrow16Sto8Ux8", "Iop_QandQRSarNnarrow32Sto16Ux4", "Iop_QandQRSarNnarrow64Sto32Ux2", "Iop_QNarrowBin16Sto8Ux16", "Iop_QNarrowBin32Sto16Ux8", "Iop_QNarrowBin16Sto8Sx16", "Iop_QNarrowBin32Sto16Sx8", "Iop_QNarrowBin16Uto8Ux16", "Iop_QNarrowBin32Uto16Ux8", "Iop_NarrowBin16to8x16", "Iop_NarrowBin32to16x8", "Iop_QNarrowBin64Sto32Sx4", "Iop_QNarrowBin64Uto32Ux4", "Iop_NarrowBin64to32x4", "Iop_NarrowUn16to8x8", "Iop_NarrowUn32to16x4", "Iop_NarrowUn64to32x2", "Iop_QNarrowUn16Sto8Sx8", "Iop_QNarrowUn32Sto16Sx4", "Iop_QNarrowUn64Sto32Sx2", "Iop_QNarrowUn16Sto8Ux8", "Iop_QNarrowUn32Sto16Ux4", "Iop_QNarrowUn64Sto32Ux2", "Iop_QNarrowUn16Uto8Ux8", "Iop_QNarrowUn32Uto16Ux4", "Iop_QNarrowUn64Uto32Ux2", "Iop_Widen8Uto16x8", "Iop_Widen16Uto32x4", "Iop_Widen32Uto64x2", "Iop_Widen8Sto16x8", "Iop_Widen16Sto32x4", "Iop_Widen32Sto64x2", "Iop_InterleaveHI8x16", "Iop_InterleaveHI16x8", "Iop_InterleaveHI32x4", "Iop_InterleaveHI64x2", "Iop_InterleaveLO8x16", "Iop_InterleaveLO16x8", "Iop_InterleaveLO32x4", "Iop_InterleaveLO64x2", "Iop_InterleaveOddLanes8x16", "Iop_InterleaveEvenLanes8x16", "Iop_InterleaveOddLanes16x8", "Iop_InterleaveEvenLanes16x8", "Iop_InterleaveOddLanes32x4", "Iop_InterleaveEvenLanes32x4", "Iop_CatOddLanes8x16", "Iop_CatOddLanes16x8", "Iop_CatOddLanes32x4", "Iop_CatEvenLanes8x16", "Iop_CatEvenLanes16x8", "Iop_CatEvenLanes32x4", "Iop_GetElem8x16", "Iop_GetElem16x8", "Iop_GetElem32x4", "Iop_GetElem64x2", "Iop_Dup8x16", "Iop_Dup16x8", "Iop_Dup32x4", "Iop_SliceV128", "Iop_Reverse8sIn16_x8", "Iop_Reverse8sIn32_x4", "Iop_Reverse16sIn32_x4", "Iop_Reverse8sIn64_x2", "Iop_Reverse16sIn64_x2", "Iop_Reverse32sIn64_x2", "Iop_Reverse1sIn8_x16", "Iop_Perm8x16", "Iop_Perm32x4", "Iop_GetMSBs8x16", "Iop_RecipEst32Ux4", "Iop_RSqrtEst32Ux4", "Iop_V256to64_0", "Iop_V256to64_1", "Iop_V256to64_2", "Iop_V256to64_3", "Iop_64x4toV256", "Iop_V256toV128_0", "Iop_V256toV128_1", "Iop_V128HLtoV256", "Iop_AndV256", "Iop_OrV256", "Iop_XorV256", "Iop_NotV256", "Iop_CmpNEZ8x32", "Iop_CmpNEZ16x16", "Iop_CmpNEZ32x8", "Iop_CmpNEZ64x4", "Iop_Add8x32", "Iop_Add16x16", "Iop_Add32x8", "Iop_Add64x4", "Iop_Sub8x32", "Iop_Sub16x16", "Iop_Sub32x8", "Iop_Sub64x4", "Iop_CmpEQ8x32", "Iop_CmpEQ16x16", "Iop_CmpEQ32x8", "Iop_CmpEQ64x4", "Iop_CmpGT8Sx32", "Iop_CmpGT16Sx16", "Iop_CmpGT32Sx8", "Iop_CmpGT64Sx4", "Iop_ShlN16x16", "Iop_ShlN32x8", "Iop_ShlN64x4", "Iop_ShrN16x16", "Iop_ShrN32x8", "Iop_ShrN64x4", "Iop_SarN16x16", "Iop_SarN32x8", "Iop_Max8Sx32", "Iop_Max16Sx16", "Iop_Max32Sx8", "Iop_Max8Ux32", "Iop_Max16Ux16", "Iop_Max32Ux8", "Iop_Min8Sx32", "Iop_Min16Sx16", "Iop_Min32Sx8", "Iop_Min8Ux32", "Iop_Min16Ux16", "Iop_Min32Ux8", "Iop_Mul16x16", "Iop_Mul32x8", "Iop_MulHi16Ux16", "Iop_MulHi16Sx16", "Iop_QAdd8Ux32", "Iop_QAdd16Ux16", "Iop_QAdd8Sx32", "Iop_QAdd16Sx16", "Iop_QSub8Ux32", "Iop_QSub16Ux16", "Iop_QSub8Sx32", "Iop_QSub16Sx16", "Iop_Avg8Ux32", "Iop_Avg16Ux16", "Iop_Perm32x8", "Iop_CipherV128", "Iop_CipherLV128", "Iop_CipherSV128", "Iop_NCipherV128", "Iop_NCipherLV128", "Iop_SHA512", "Iop_SHA256", "Iop_Add64Fx4", "Iop_Sub64Fx4", "Iop_Mul64Fx4", "Iop_Div64Fx4", "Iop_Add32Fx8", "Iop_Sub32Fx8", "Iop_Mul32Fx8", "Iop_Div32Fx8", "Iop_Sqrt32Fx8", "Iop_Sqrt64Fx4", "Iop_RSqrtEst32Fx8", "Iop_RecipEst32Fx8", "Iop_Max32Fx8", "Iop_Min32Fx8", "Iop_Max64Fx4", "Iop_Min64Fx4", "Iop_LAST"]
operations = { }
classified = set()
unclassified = set()
unsupported = set()
explicit_attrs = {
    'Iop_Yl2xF64': {
        'generic_name': 'Yl2x',
        'to_size': 64,
    },
    'Iop_Yl2xp1F64': {
        'generic_name': 'Yl2xp1',
        'to_size': 64,
    },
    'Iop_AddF64r32': {
        'generic_name': 'Add',
        'from_size': 64,
        'from_type' : 'F',
        'to_size': 32,
        'to_type' : 'F'
    },
    'Iop_SubF64r32': {
        'generic_name': 'Sub',
        'from_size': 64,
        'from_type' : 'F',
        'to_size': 32,
        'to_type' : 'F'
    },
    'Iop_MulF64r32': {
        'generic_name': 'Mul',
        'from_size': 64,
        'from_type' : 'F',
        'to_size': 32,
        'to_type' : 'F'
    },
    'Iop_DivF64r32': {
        'generic_name': 'Div',
        'from_size': 64,
        'from_type' : 'F',
        'to_size': 32,
        'to_type' : 'F'
    },
	'Iop_SetV128lo64': {
        'generic_name': 'Set',
        'from_size': 128,
        'from_type' : 'V',
        'to_size': 128,
        'to_type' : 'V'
    },
	'Iop_SetV128lo32': {
        'generic_name': 'Set',
        'from_size': 128,
        'from_type' : 'V',
        'to_size': 128,
        'to_type' : 'V'
    },
}


def make_operations():
    for p in all_operations:
        if p in ('Iop_INVALID', 'Iop_LAST'):
            continue

        if p in explicit_attrs:
            attrs = explicit_attrs[p]
        else:
            attrs = op_attrs(p)

        if attrs is None:
            unclassified.add(p)
        else:
            classified.add(p)
            try:
                simir = SimIROp(p, **attrs)
                if(simir._supported == True):
                    operations[p] = simir
            except:
                print "error"
                unsupported.add(p)

    print "%d matched (%d supported) and %d unmatched operations" % (len(classified), len(operations), len(unclassified))

    with open('maps.json', 'w') as outfile:
        json.dump(operations, outfile, cls=MyEncoder, sort_keys=True, indent=4)
    with open('../../kam1n0-core/bin/lib/maps.json', 'w') as outfile:
        json.dump(operations, outfile, cls=MyEncoder, sort_keys=True, indent=4)


arithmetic_operation_map = {
    'Add': '__add__',
    'Sub': '__sub__',
    'Mul': '__mul__',
    'Div': '__div__',
    'Neg': 'Neg',
    'Abs': 'Abs',
}
shift_operation_map = {
    'Shl': '__lshift__',
    'Shr': 'LShR',
    'Sar': '__rshift__',
}
bitwise_operation_map = {
    'Xor': '__xor__',
    'Or': '__or__',
    'And': '__and__',
    'Not': '__invert__',
}

generic_names = set()
conversions = collections.defaultdict(list)
unsupported_conversions = [ ]
add_operations = [ ]
other_operations = [ ]
vector_operations = [ ]
fp_ops = set()
common_unsupported_generics = collections.Counter()


def supports_vector(f):
    f.supports_vector = True
    return f



class MyEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__


class SimIROp(object):
    """
    A symbolic version of a Vex IR operation.
    """
    def __init__(self, name, **attrs):
        l.debug("Creating SimIROp(%s)", name)
        self.name = name

        self._generic_name = None
        self._from_size = None
        self._from_side = None
        self._from_type = None
        self._from_signed = None
        self._to_size = None
        self._to_type = None
        self._to_signed = None
        self._conversion = None
        self._vector_size = None
        self._vector_signed = None
        self._vector_type = None
        self._vector_zero = None
        self._vector_count = None

        self._rounding_mode = None

        for k,v in attrs.items():
            if v is not None and ('size' in k or 'count' in k):
                v = int(v)
            setattr(self, '_%s'%k, v)

        if len({self._vector_type, self._from_type, self._to_type} & {'F', 'D'}) != 0:
            # print self.op_attrs
            self._float = True

            if len({self._vector_type, self._from_type, self._to_type} & {'D'}) != 0:
                print "BCD ops aren't supported %s" % name
                self._supported = False
        else:
            self._float = False
        self._supported = True


make_operations()
