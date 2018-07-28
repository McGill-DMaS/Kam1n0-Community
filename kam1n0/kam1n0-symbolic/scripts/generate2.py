#!/usr/bin/env python

import json
from json import JSONEncoder

##################
### x86* data ###
##################

data = {
    'AMD64': {
        'CondTypes': { },
        'CondBitOffsets': { },
        'CondBitMasks': { },
        'OpTypes': { }
    }, 'X86': {
        'CondTypes': { },
        'CondBitOffsets': { },
        'CondBitMasks': { },
        'OpTypes': { }
    }, 'ARM': {
        'CondTypes': { },
        'CondBitOffsets': { },
        'CondBitMasks': { },
        'OpTypes': { }
    }
    , 'ARM64': {
        'CondTypes': { },
        'CondBitOffsets': { },
        'CondBitMasks': { },
        'OpTypes': { }
    }
}

# condition types
data['AMD64']['CondTypes']['CondO']      = 0  # /* overflow           */
data['AMD64']['CondTypes']['CondNO']     = 1  # /* no overflow        */
data['AMD64']['CondTypes']['CondB']      = 2  # /* below              */
data['AMD64']['CondTypes']['CondNB']     = 3  # /* not below          */
data['AMD64']['CondTypes']['CondZ']      = 4  # /* zero               */
data['AMD64']['CondTypes']['CondNZ']     = 5  # /* not zero           */
data['AMD64']['CondTypes']['CondBE']     = 6  # /* below or equal     */
data['AMD64']['CondTypes']['CondNBE']    = 7  # /* not below or equal */
data['AMD64']['CondTypes']['CondS']      = 8  # /* negative           */
data['AMD64']['CondTypes']['CondNS']     = 9  # /* not negative       */
data['AMD64']['CondTypes']['CondP']      = 10 # /* parity even        */
data['AMD64']['CondTypes']['CondNP']     = 11 # /* not parity even    */
data['AMD64']['CondTypes']['CondL']      = 12 # /* jump less          */
data['AMD64']['CondTypes']['CondNL']     = 13 # /* not less           */
data['AMD64']['CondTypes']['CondLE']     = 14 # /* less or equal      */
data['AMD64']['CondTypes']['CondNLE']    = 15 # /* not less or equal  */

# condition bit offsets
data['AMD64']['CondBitOffsets']['CC_SHIFT_O'] = 11
data['AMD64']['CondBitOffsets']['CC_SHIFT_S'] = 7
data['AMD64']['CondBitOffsets']['CC_SHIFT_Z'] = 6
data['AMD64']['CondBitOffsets']['CC_SHIFT_A'] = 4
data['AMD64']['CondBitOffsets']['CC_SHIFT_C'] = 0
data['AMD64']['CondBitOffsets']['CC_SHIFT_P'] = 2

# masks
data['AMD64']['CondBitMasks']['CC_MASK_O'] = (1 << data['AMD64']['CondBitOffsets']['CC_SHIFT_O'])
data['AMD64']['CondBitMasks']['CC_MASK_S'] = (1 << data['AMD64']['CondBitOffsets']['CC_SHIFT_S'])
data['AMD64']['CondBitMasks']['CC_MASK_Z'] = (1 << data['AMD64']['CondBitOffsets']['CC_SHIFT_Z'])
data['AMD64']['CondBitMasks']['CC_MASK_A'] = (1 << data['AMD64']['CondBitOffsets']['CC_SHIFT_A'])
data['AMD64']['CondBitMasks']['CC_MASK_C'] = (1 << data['AMD64']['CondBitOffsets']['CC_SHIFT_C'])
data['AMD64']['CondBitMasks']['CC_MASK_P'] = (1 << data['AMD64']['CondBitOffsets']['CC_SHIFT_P'])

# operation types
data['AMD64']['OpTypes']['CC_OP_COPY'] = 0
data['AMD64']['OpTypes']['CC_OP_ADDB'] = 1
data['AMD64']['OpTypes']['CC_OP_ADDW'] = 2
data['AMD64']['OpTypes']['CC_OP_ADDL'] = 3
data['AMD64']['OpTypes']['CC_OP_ADDQ'] = 4
data['AMD64']['OpTypes']['CC_OP_SUBB'] = 5
data['AMD64']['OpTypes']['CC_OP_SUBW'] = 6
data['AMD64']['OpTypes']['CC_OP_SUBL'] = 7
data['AMD64']['OpTypes']['CC_OP_SUBQ'] = 8
data['AMD64']['OpTypes']['CC_OP_ADCB'] = 9
data['AMD64']['OpTypes']['CC_OP_ADCW'] = 10
data['AMD64']['OpTypes']['CC_OP_ADCL'] = 11
data['AMD64']['OpTypes']['CC_OP_ADCQ'] = 12
data['AMD64']['OpTypes']['CC_OP_SBBB'] = 13
data['AMD64']['OpTypes']['CC_OP_SBBW'] = 14
data['AMD64']['OpTypes']['CC_OP_SBBL'] = 15
data['AMD64']['OpTypes']['CC_OP_SBBQ'] = 16
data['AMD64']['OpTypes']['CC_OP_LOGICB'] = 17
data['AMD64']['OpTypes']['CC_OP_LOGICW'] = 18
data['AMD64']['OpTypes']['CC_OP_LOGICL'] = 19
data['AMD64']['OpTypes']['CC_OP_LOGICQ'] = 20
data['AMD64']['OpTypes']['CC_OP_INCB'] = 21
data['AMD64']['OpTypes']['CC_OP_INCW'] = 22
data['AMD64']['OpTypes']['CC_OP_INCL'] = 23
data['AMD64']['OpTypes']['CC_OP_INCQ'] = 24
data['AMD64']['OpTypes']['CC_OP_DECB'] = 25
data['AMD64']['OpTypes']['CC_OP_DECW'] = 26
data['AMD64']['OpTypes']['CC_OP_DECL'] = 27
data['AMD64']['OpTypes']['CC_OP_DECQ'] = 28
data['AMD64']['OpTypes']['CC_OP_SHLB'] = 29
data['AMD64']['OpTypes']['CC_OP_SHLW'] = 30
data['AMD64']['OpTypes']['CC_OP_SHLL'] = 31
data['AMD64']['OpTypes']['CC_OP_SHLQ'] = 32
data['AMD64']['OpTypes']['CC_OP_SHRB'] = 33
data['AMD64']['OpTypes']['CC_OP_SHRW'] = 34
data['AMD64']['OpTypes']['CC_OP_SHRL'] = 35
data['AMD64']['OpTypes']['CC_OP_SHRQ'] = 36
data['AMD64']['OpTypes']['CC_OP_ROLB'] = 37
data['AMD64']['OpTypes']['CC_OP_ROLW'] = 38
data['AMD64']['OpTypes']['CC_OP_ROLL'] = 39
data['AMD64']['OpTypes']['CC_OP_ROLQ'] = 40
data['AMD64']['OpTypes']['CC_OP_RORB'] = 41
data['AMD64']['OpTypes']['CC_OP_RORW'] = 42
data['AMD64']['OpTypes']['CC_OP_RORL'] = 43
data['AMD64']['OpTypes']['CC_OP_RORQ'] = 44
data['AMD64']['OpTypes']['CC_OP_UMULB'] = 45
data['AMD64']['OpTypes']['CC_OP_UMULW'] = 46
data['AMD64']['OpTypes']['CC_OP_UMULL'] = 47
data['AMD64']['OpTypes']['CC_OP_UMULQ'] = 48
data['AMD64']['OpTypes']['CC_OP_SMULB'] = 49
data['AMD64']['OpTypes']['CC_OP_SMULW'] = 50
data['AMD64']['OpTypes']['CC_OP_SMULL'] = 51
data['AMD64']['OpTypes']['CC_OP_SMULQ'] = 52
data['AMD64']['OpTypes']['CC_OP_NUMBER'] = 53

data['X86']['CondTypes']['CondO']      = 0
data['X86']['CondTypes']['CondNO']     = 1
data['X86']['CondTypes']['CondB']      = 2
data['X86']['CondTypes']['CondNB']     = 3
data['X86']['CondTypes']['CondZ']      = 4
data['X86']['CondTypes']['CondNZ']     = 5
data['X86']['CondTypes']['CondBE']     = 6
data['X86']['CondTypes']['CondNBE']    = 7
data['X86']['CondTypes']['CondS']      = 8
data['X86']['CondTypes']['CondNS']     = 9
data['X86']['CondTypes']['CondP']      = 10
data['X86']['CondTypes']['CondNP']     = 11
data['X86']['CondTypes']['CondL']      = 12
data['X86']['CondTypes']['CondNL']     = 13
data['X86']['CondTypes']['CondLE']     = 14
data['X86']['CondTypes']['CondNLE']    = 15
data['X86']['CondTypes']['CondAlways'] = 16

data['X86']['CondBitOffsets']['CC_SHIFT_O'] = 11
data['X86']['CondBitOffsets']['CC_SHIFT_S'] = 7
data['X86']['CondBitOffsets']['CC_SHIFT_Z'] = 6
data['X86']['CondBitOffsets']['CC_SHIFT_A'] = 4
data['X86']['CondBitOffsets']['CC_SHIFT_C'] = 0
data['X86']['CondBitOffsets']['CC_SHIFT_P'] = 2

# masks
data['X86']['CondBitMasks']['CC_MASK_O'] = (1 << data['X86']['CondBitOffsets']['CC_SHIFT_O'])
data['X86']['CondBitMasks']['CC_MASK_S'] = (1 << data['X86']['CondBitOffsets']['CC_SHIFT_S'])
data['X86']['CondBitMasks']['CC_MASK_Z'] = (1 << data['X86']['CondBitOffsets']['CC_SHIFT_Z'])
data['X86']['CondBitMasks']['CC_MASK_A'] = (1 << data['X86']['CondBitOffsets']['CC_SHIFT_A'])
data['X86']['CondBitMasks']['CC_MASK_C'] = (1 << data['X86']['CondBitOffsets']['CC_SHIFT_C'])
data['X86']['CondBitMasks']['CC_MASK_P'] = (1 << data['X86']['CondBitOffsets']['CC_SHIFT_P'])

data['X86']['OpTypes']['CC_OP_COPY'] = 0
data['X86']['OpTypes']['CC_OP_ADDB'] = 1
data['X86']['OpTypes']['CC_OP_ADDW'] = 2
data['X86']['OpTypes']['CC_OP_ADDL'] = 3
data['X86']['OpTypes']['CC_OP_SUBB'] = 4
data['X86']['OpTypes']['CC_OP_SUBW'] = 5
data['X86']['OpTypes']['CC_OP_SUBL'] = 6
data['X86']['OpTypes']['CC_OP_ADCB'] = 7
data['X86']['OpTypes']['CC_OP_ADCW'] = 8
data['X86']['OpTypes']['CC_OP_ADCL'] = 9
data['X86']['OpTypes']['CC_OP_SBBB'] = 10
data['X86']['OpTypes']['CC_OP_SBBW'] = 11
data['X86']['OpTypes']['CC_OP_SBBL'] = 12
data['X86']['OpTypes']['CC_OP_LOGICB'] = 13
data['X86']['OpTypes']['CC_OP_LOGICW'] = 14
data['X86']['OpTypes']['CC_OP_LOGICL'] = 15
data['X86']['OpTypes']['CC_OP_INCB'] = 16
data['X86']['OpTypes']['CC_OP_INCW'] = 17
data['X86']['OpTypes']['CC_OP_INCL'] = 18
data['X86']['OpTypes']['CC_OP_DECB'] = 19
data['X86']['OpTypes']['CC_OP_DECW'] = 20
data['X86']['OpTypes']['CC_OP_DECL'] = 21
data['X86']['OpTypes']['CC_OP_SHLB'] = 22
data['X86']['OpTypes']['CC_OP_SHLW'] = 23
data['X86']['OpTypes']['CC_OP_SHLL'] = 24
data['X86']['OpTypes']['CC_OP_SHRB'] = 25
data['X86']['OpTypes']['CC_OP_SHRW'] = 26
data['X86']['OpTypes']['CC_OP_SHRL'] = 27
data['X86']['OpTypes']['CC_OP_ROLB'] = 28
data['X86']['OpTypes']['CC_OP_ROLW'] = 29
data['X86']['OpTypes']['CC_OP_ROLL'] = 30
data['X86']['OpTypes']['CC_OP_RORB'] = 31
data['X86']['OpTypes']['CC_OP_RORW'] = 32
data['X86']['OpTypes']['CC_OP_RORL'] = 33
data['X86']['OpTypes']['CC_OP_UMULB'] = 34
data['X86']['OpTypes']['CC_OP_UMULW'] = 35
data['X86']['OpTypes']['CC_OP_UMULL'] = 36
data['X86']['OpTypes']['CC_OP_SMULB'] = 37
data['X86']['OpTypes']['CC_OP_SMULW'] = 38
data['X86']['OpTypes']['CC_OP_SMULL'] = 39
data['X86']['OpTypes']['CC_OP_NUMBER'] = 40

data['X86']['OpTypes']['CC_OP_SMULQ'] = -100
data['X86']['OpTypes']['CC_OP_UMULQ'] = -100
data['X86']['OpTypes']['CC_OP_RORQ'] = -100
data['X86']['OpTypes']['CC_OP_ROLQ'] = -100
data['X86']['OpTypes']['CC_OP_SHRQ'] = -100
data['X86']['OpTypes']['CC_OP_SHLQ'] = -100
data['X86']['OpTypes']['CC_OP_DECQ'] = -100
data['X86']['OpTypes']['CC_OP_INCQ'] = -100
data['X86']['OpTypes']['CC_OP_LOGICQ'] = -100
data['X86']['OpTypes']['CC_OP_SBBQ'] = -100
data['X86']['OpTypes']['CC_OP_ADCQ'] = -100
data['X86']['OpTypes']['CC_OP_SUBQ'] = -100
data['X86']['OpTypes']['CC_OP_ADDQ'] = -100


# ARM

data['ARM']['CondTypes']['ARMCondEQ'] =  0 #   /* equal                         : Z=1 */
data['ARM']['CondTypes']['ARMCondNE'] =  1 #   /* not equal                     : Z=0 */
data['ARM']['CondTypes']['ARMCondHS'] =  2 #   /* >=u (higher or same)          : C=1 */
data['ARM']['CondTypes']['ARMCondLO'] =  3 #   /* <u  (lower)                   : C=0 */
data['ARM']['CondTypes']['ARMCondMI'] =  4 #   /* minus (negative)              : N=1 */
data['ARM']['CondTypes']['ARMCondPL'] =  5 #   /* plus (zero or +ve)            : N=0 */
data['ARM']['CondTypes']['ARMCondVS'] =  6 #   /* overflow                      : V=1 */
data['ARM']['CondTypes']['ARMCondVC'] =  7 #   /* no overflow                   : V=0 */
data['ARM']['CondTypes']['ARMCondHI'] =  8 #   /* >u   (higher)                 : C=1 && Z=0 */
data['ARM']['CondTypes']['ARMCondLS'] =  9 #   /* <=u  (lower or same)          : C=0 || Z=1 */
data['ARM']['CondTypes']['ARMCondGE'] =  10 #  /* >=s (signed greater or equal) : N=V */
data['ARM']['CondTypes']['ARMCondLT'] =  11 #  /* <s  (signed less than)        : N!=V */
data['ARM']['CondTypes']['ARMCondGT'] =  12 #  /* >s  (signed greater)          : Z=0 && N=V */
data['ARM']['CondTypes']['ARMCondLE'] =  13 #  /* <=s (signed less or equal)    : Z=1 || N!=V */
data['ARM']['CondTypes']['ARMCondAL'] =  14 #  /* always (unconditional)        : 1 */
data['ARM']['CondTypes']['ARMCondNV'] =  15 #   /* never (unconditional):        : 0 */

data['ARM']['OpTypes']['CC_OP_COPY'] =  0   # /* DEP1'] =  NZCV in 31:28, DEP2'] =  0, DEP3'] =  0 just copy DEP1 to output */
data['ARM']['OpTypes']['CC_OP_ADD'] =  1    # /* DEP1'] =  argL (Rn)'] =   DEP2'] =  argR (shifter_op)'] =   DEP3'] =  0 */
data['ARM']['OpTypes']['CC_OP_SUB'] =  2    # /* DEP1'] =  argL (Rn)'] =   DEP2'] =  argR (shifter_op)'] =   DEP3'] =  0 */
data['ARM']['OpTypes']['CC_OP_ADC'] =  3    # /* DEP1'] =  argL (Rn)'] =   DEP2'] =  arg2 (shifter_op)'] =   DEP3'] =  oldC (in LSB) */
data['ARM']['OpTypes']['CC_OP_SBB'] =  4    # /* DEP1'] =  argL (Rn)'] =   DEP2'] =  arg2 (shifter_op)'] =   DEP3'] =  oldC (in LSB) */
data['ARM']['OpTypes']['CC_OP_LOGIC'] =  5  # /* DEP1'] =  result'] =   DEP2'] =  shifter_carry_out (in LSB)'] =   DEP3'] =  old V flag (in LSB) */
data['ARM']['OpTypes']['CC_OP_MUL'] =  6    # /* DEP1'] =  result'] =   DEP2'] =  0'] =   DEP3'] =  oldC:old_V (in bits 1:0) */
data['ARM']['OpTypes']['CC_OP_MULL'] =  7   # /* DEP1'] =  resLO32'] =   DEP2'] =  resHI32'] =   DEP3'] =  oldC:old_V (in bits 1:0) */
data['ARM']['OpTypes']['CC_OP_NUMBER'] =  8


data['ARM']['CondBitOffsets']['CC_SHIFT_N'] = 31
data['ARM']['CondBitOffsets']['CC_SHIFT_Z'] = 30
data['ARM']['CondBitOffsets']['CC_SHIFT_C'] = 29
data['ARM']['CondBitOffsets']['CC_SHIFT_V'] = 28
data['ARM']['CondBitOffsets']['CC_SHIFT_Q'] = 27

data['ARM']['CondBitMasks']['CC_MASK_N'] = (1 << data['ARM']['CondBitOffsets']['CC_SHIFT_N'])
data['ARM']['CondBitMasks']['CC_MASK_Z'] = (1 << data['ARM']['CondBitOffsets']['CC_SHIFT_Z'])
data['ARM']['CondBitMasks']['CC_MASK_C'] = (1 << data['ARM']['CondBitOffsets']['CC_SHIFT_C'])
data['ARM']['CondBitMasks']['CC_MASK_V'] = (1 << data['ARM']['CondBitOffsets']['CC_SHIFT_V'])
data['ARM']['CondBitMasks']['CC_MASK_Q'] = (1 << data['ARM']['CondBitOffsets']['CC_SHIFT_Q'])


# ARM64

data['ARM64']['CondTypes']['ARM64CondEQ '] =  0  #/* equal                         : Z'] = 1 */
data['ARM64']['CondTypes']['ARM64CondNE '] =  1  #/* not equal                     : Z'] = 0 */
data['ARM64']['CondTypes']['ARM64CondCS '] =  2  #/* >'] = u (higher or same) (aka HS) : C'] = 1 */
data['ARM64']['CondTypes']['ARM64CondCC '] =  3  #/* <u  (lower)          (aka LO) : C'] = 0 */
data['ARM64']['CondTypes']['ARM64CondMI '] =  4  #/* minus (negative)              : N'] = 1 */
data['ARM64']['CondTypes']['ARM64CondPL '] =  5  #/* plus (zero or +ve)            : N'] = 0 */
data['ARM64']['CondTypes']['ARM64CondVS '] =  6  #/* overflow                      : V'] = 1 */
data['ARM64']['CondTypes']['ARM64CondVC '] =  7  #/* no overflow                   : V'] = 0 */
data['ARM64']['CondTypes']['ARM64CondHI '] =  8  #/* >u   (higher)                 : C'] = 1 && Z'] = 0 */
data['ARM64']['CondTypes']['ARM64CondLS '] =  9  #/* <'] = u  (lower or same)          : C'] = 0 || Z'] = 1 */
data['ARM64']['CondTypes']['ARM64CondGE '] =  10 #/* >'] = s (signed greater or equal) : N'] = V */
data['ARM64']['CondTypes']['ARM64CondLT '] =  11 #/* <s  (signed less than)        : N!'] = V */
data['ARM64']['CondTypes']['ARM64CondGT '] =  12 #/* >s  (signed greater)          : Z'] = 0 && N'] = V */
data['ARM64']['CondTypes']['ARM64CondLE '] =  13 #/* <'] = s (signed less or equal)    : Z'] = 1 || N!'] = V */
data['ARM64']['CondTypes']['ARM64CondAL '] =  14 #/* always (unconditional)        : 1 */
data['ARM64']['CondTypes']['ARM64CondNV '] =  15 #/* always (unconditional)        : 1 */

data['ARM64']['OpTypes']['CC_OP_COPY'] = 0      #/* DEP1 '] =  NZCV in 31:28, DEP2 '] =  0, DEP3 '] =  0 just copy DEP1 to output */
data['ARM64']['OpTypes']['CC_OP_ADD32'] = 1     #/* DEP1 '] =  argL (Rn), DEP2 '] =  argR (shifter_op), DEP3 '] =  0 */
data['ARM64']['OpTypes']['CC_OP_ADD64'] = 2     #/* DEP1 '] =  argL (Rn), DEP2 '] =  argR (shifter_op), DEP3 '] =  0 */
data['ARM64']['OpTypes']['CC_OP_SUB32'] = 3     #/* DEP1 '] =  argL (Rn), DEP2 '] =  argR (shifter_op), DEP3 '] =  0 */
data['ARM64']['OpTypes']['CC_OP_SUB64'] = 4     #/* DEP1 '] =  argL (Rn), DEP2 '] =  argR (shifter_op), DEP3 '] =  0 */
data['ARM64']['OpTypes']['CC_OP_ADC32'] = 5     #/* DEP1 '] =  argL (Rn), DEP2 '] =  arg2 (shifter_op), DEP3 '] =  oldC (in LSB) */
data['ARM64']['OpTypes']['CC_OP_ADC64'] = 6     #/* DEP1 '] =  argL (Rn), DEP2 '] =  arg2 (shifter_op), DEP3 '] =  oldC (in LSB) */
data['ARM64']['OpTypes']['CC_OP_SBC32'] = 7     #/* DEP1 '] =  argL (Rn), DEP2 '] =  arg2 (shifter_op), DEP3 '] =  oldC (in LSB) */
data['ARM64']['OpTypes']['CC_OP_SBC64'] = 8     #/* DEP1 '] =  argL (Rn), DEP2 '] =  arg2 (shifter_op), DEP3 '] =  oldC (in LSB) */
data['ARM64']['OpTypes']['CC_OP_LOGIC32'] = 9   #/* DEP1 '] =  result, DEP2 '] =  0, DEP3 '] =  0 */
data['ARM64']['OpTypes']['CC_OP_LOGIC64'] = 10  #/* DEP1 '] =  result, DEP2 '] =  0, DEP3 '] =  0 */
data['ARM64']['OpTypes']['CC_OP_NUMBER'] = 11   #


data['ARM64']['CondBitOffsets']['CC_SHIFT_N'] = 31
data['ARM64']['CondBitOffsets']['CC_SHIFT_Z'] = 30
data['ARM64']['CondBitOffsets']['CC_SHIFT_C'] = 29
data['ARM64']['CondBitOffsets']['CC_SHIFT_V'] = 28

data['ARM64']['CondBitMasks']['CC_MASK_N'] = (1 << data['ARM64']['CondBitOffsets']['CC_SHIFT_N'])
data['ARM64']['CondBitMasks']['CC_MASK_Z'] = (1 << data['ARM64']['CondBitOffsets']['CC_SHIFT_Z'])
data['ARM64']['CondBitMasks']['CC_MASK_C'] = (1 << data['ARM64']['CondBitOffsets']['CC_SHIFT_C'])
data['ARM64']['CondBitMasks']['CC_MASK_V'] = (1 << data['ARM64']['CondBitOffsets']['CC_SHIFT_V'])




data_inverted = { k_arch: { k_data_class: {y:x for (x,y) in d_data_class.iteritems()} for k_data_class, d_data_class in d_arch.iteritems() } for k_arch,d_arch in data.iteritems() }

data['AMD64']['size'] = 64
data['X86']['size'] = 32
data['ARM']['size'] = 32
data['ARM64']['size'] = 64

data['X86']['CondTypesRev'] = data['X86']['CondTypes']
data['X86']['CondTypes'] = data_inverted['X86']['CondTypes']
data['X86']['OpTypesRev'] = data['X86']['OpTypes']
data['X86']['OpTypes'] = data_inverted['X86']['OpTypes']

data['AMD64']['CondTypesRev'] = data['AMD64']['CondTypes']
data['AMD64']['CondTypes'] = data_inverted['AMD64']['CondTypes']
data['AMD64']['OpTypesRev'] = data['AMD64']['OpTypes']
data['AMD64']['OpTypes'] = data_inverted['AMD64']['OpTypes']

data['ARM']['CondTypesRev'] = data['ARM']['CondTypes']
data['ARM']['CondTypes'] = data_inverted['ARM']['CondTypes']
data['ARM']['OpTypesRev'] = data['ARM']['OpTypes']
data['ARM']['OpTypes'] = data_inverted['ARM']['OpTypes']

data['ARM64']['CondTypesRev'] = data['ARM64']['CondTypes']
data['ARM64']['CondTypes'] = data_inverted['ARM64']['CondTypes']
data['ARM64']['OpTypesRev'] = data['ARM64']['OpTypes']
data['ARM64']['OpTypes'] = data_inverted['ARM64']['OpTypes']


with open('maps.ccall.json', 'w') as outfile:
    json.dump(data, outfile, sort_keys=True, indent=4)
with open('../../kam1n0-core/bin/lib/maps.ccall.json', 'w') as outfile:
    json.dump(data, outfile, sort_keys=True, indent=4)
