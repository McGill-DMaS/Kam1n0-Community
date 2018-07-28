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
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libvex.h>
#include "ca_mcgill_sis_dmas_kam1n0_vex_VEXIRBB.h"

// #define __debug_kam1n0__

// Some info required for translation 
extern VexTranslateArgs vta;

extern char *last_error;

//
// Initializes VEX. This function must be called before vex_insn
// can be used.
//
void vex_init(void);
int main();
//
// Translates assembly instructions and blocks into VEX
IRSB *vex_block_bytes(VexArch guest, VexArchInfo archinfo,
		unsigned char *instructions, unsigned long long block_addr,
		unsigned int num_bytes, int basic_only);
IRSB *vex_block_inst(VexArch guest, VexArchInfo archinfo,
		unsigned char *instructions, unsigned long long block_addr,
		unsigned int num_inst);
unsigned int vex_count_instructions(VexArch guest, VexArchInfo archinfo,
		unsigned char *instructions, unsigned long long block_addr,
		unsigned int num_bytes, int basic_only);
void set_iropt_level(int level);

//jni area: (machine generated code)
jobject create_VexCall(JNIEnv * jenv, jint regparms, jobject name_String,
		jlong address_unsigned, jint mcx_mask_usigned) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/VexCall;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(ILjava/lang/String;JI)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, regparms,
			name_String, address_unsigned, mcx_mask_usigned);
}
jobject create_ExBinder(JNIEnv * jenv, jint binder) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExBinder;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(I)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, binder);
}
jobject create_ExBinop(JNIEnv * jenv, jobject operation_VexOperation,
		jobject exp1_VexExpression, jobject exp2_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExBinop;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexOperation;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			operation_VexOperation, exp1_VexExpression, exp2_VexExpression);
}
jobject create_ExCCall(JNIEnv * jenv, jobject callee_VexCall,
		jobject type_VexVariableType, jobject args_ArrayList) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExCCall;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexCall;Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexVariableType;Ljava/util/ArrayList;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, callee_VexCall,
			type_VexVariableType, args_ArrayList);
}
jobject create_ExConst(JNIEnv * jenv, jobject constant_VexConstant) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExConst;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(Lca/mcgill/sis/dmas/kam1n0/vex/VexConstant;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			constant_VexConstant);
}
jobject create_ExGet(JNIEnv * jenv, jint offset, jobject type_VexVariableType) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExGet;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(ILca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexVariableType;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, offset,
			type_VexVariableType);
}
jobject create_ExGetI(JNIEnv * jenv, jobject descr_IRRegArray,
		jobject expression_VexExpression, jint bias) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExGetI;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/variable/IRRegArray;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;I)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, descr_IRRegArray,
			expression_VexExpression, bias);
}
jobject create_ExLoad(JNIEnv * jenv, jobject endness_VexEndnessType,
		jobject type_VexVariableType, jobject expression_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExLoad;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexVariableType;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			endness_VexEndnessType, type_VexVariableType,
			expression_VexExpression);
}
jobject create_ExQop(JNIEnv * jenv, jobject operation_VexOperation,
		jobject exp1_VexExpression, jobject exp2_VexExpression,
		jobject exp3_VexExpression, jobject exp4_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExQop;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexOperation;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			operation_VexOperation, exp1_VexExpression, exp2_VexExpression,
			exp3_VexExpression, exp4_VexExpression);
}
jobject create_ExRdTmp(JNIEnv * jenv, jint valunsigned) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExRdTmp;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(I)V");
	jobject tmpVal = (*jenv)->NewObject(jenv, target_class, constructor,
			valunsigned);
	return tmpVal;
}
jobject create_ExTriop(JNIEnv * jenv, jobject operation_VexOperation,
		jobject exp1_VexExpression, jobject exp2_VexExpression,
		jobject exp3_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExTriop;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexOperation;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			operation_VexOperation, exp1_VexExpression, exp2_VexExpression,
			exp3_VexExpression);
}
jobject create_ExUnop(JNIEnv * jenv, jobject operation_VexOperation,
		jobject exp1_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExUnop;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexOperation;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			operation_VexOperation, exp1_VexExpression);
}
jobject create_ExITE(JNIEnv * jenv, jobject cond_VexExpression,
		jobject iftrue_VexExpression, jobject iffalse_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExITE;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			cond_VexExpression, iftrue_VexExpression, iffalse_VexExpression);
}
jobject create_ExVECRET(JNIEnv * jenv) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExVECRET;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"()V");
	return (*jenv)->NewObject(jenv, target_class, constructor);
}
jobject create_ExBBPTR(JNIEnv * jenv) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/expression/ExBBPTR;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"()V");
	return (*jenv)->NewObject(jenv, target_class, constructor);
}
jobject create_StmAbiHint(JNIEnv * jenv, jobject base_VexExpression, jint len,
		jobject nia_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmAbiHint;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;ILca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			base_VexExpression, len, nia_VexExpression);
}
jobject create_StmCAS(JNIEnv * jenv, jint oldHi_unsigned, jint oldLo_unsigned,
		jobject endness_VexEndnessType, jobject expdHi_VexExpression,
		jobject expdLo_VexExpression, jobject dataHi_VexExpression,
		jobject dataLow_VexExpression, jobject dataAddr_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmCAS;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(IILca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, oldHi_unsigned,
			oldLo_unsigned, endness_VexEndnessType, expdHi_VexExpression,
			expdLo_VexExpression, dataHi_VexExpression, dataLow_VexExpression, dataAddr_VexExpression);
}
jobject create_StmDirty(JNIEnv * jenv, jobject cee_VexCall,
		jobject guard_VexExpression, jobject args_List, jint tmp_unsigned,
		jobject mFx_StmDirtyEffect, jobject mAddr_VexExpression, jint mSize,
		jobject fxStates_ArrayList) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmDirty;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexCall;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Ljava/util/List;ILca/mcgill/sis/dmas/kam1n0/vex/enumeration/StmDirtyEffect;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;ILjava/util/ArrayList;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, cee_VexCall,
			guard_VexExpression, args_List, tmp_unsigned, mFx_StmDirtyEffect,
			mAddr_VexExpression, mSize, fxStates_ArrayList);
}
jobject create_StmDirtyFxStat(JNIEnv * jenv, jobject fx_StmDirtyEffect,
		jint offset_unsigned, jint size_unsigned, jint nReapts_unsigned,
		jint repeat_len_unsigned) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmDirtyFxStat;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/StmDirtyEffect;IIII)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			fx_StmDirtyEffect, offset_unsigned, size_unsigned, nReapts_unsigned,
			repeat_len_unsigned);
}
jobject create_StmExit(JNIEnv * jenv, jobject guard_VexExpression,
		jobject dst_VexConstant, jobject jumpKind_VexJumpKind,
		jint offsetIP_unsigned) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmExit;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexConstant;Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexJumpKind;I)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			guard_VexExpression, dst_VexConstant, jumpKind_VexJumpKind,
			offsetIP_unsigned);
}
jobject create_StmIMark(JNIEnv * jenv, jlong addr_unsigned, jint len_unsigned,
		jbyte delta_unsigned) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmIMark;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(JIB)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, addr_unsigned,
			len_unsigned, delta_unsigned);
}
jobject create_StmLLSC(JNIEnv * jenv, jobject endness_VexEndnessType,
		jint result_unsigned, jobject addr_VexExpression,
		jobject storedata_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmLLSC;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;ILca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			endness_VexEndnessType, result_unsigned, addr_VexExpression,
			storedata_VexExpression);
}
jobject create_StmLoadG(JNIEnv * jenv, jobject end_VexEndnessType,
		jobject cvt_StmLoadGType, jint dst_unsigned, jobject addr_VexExpression,
		jobject alt_VexExpression, jobject guard_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmLoadG;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/StmLoadGType;ILca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			end_VexEndnessType, cvt_StmLoadGType, dst_unsigned,
			addr_VexExpression, alt_VexExpression, guard_VexExpression);
}
jobject create_StmMBE(JNIEnv * jenv, jboolean imbe_fence_or_cancelreservation) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmMBE;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(Z)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			imbe_fence_or_cancelreservation);
}
jobject create_StmNoOp(JNIEnv * jenv) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmNoOp;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"()V");
	return (*jenv)->NewObject(jenv, target_class, constructor);
}
jobject create_StmPut(JNIEnv * jenv, jint offset, jobject data_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmPut;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(ILca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, offset,
			data_VexExpression);
}
jobject create_StmPutI(JNIEnv * jenv, jobject descr_IRRegArray,
		jobject ix_VexExpression, jint bias, jobject data_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmPutI;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/variable/IRRegArray;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;ILca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, descr_IRRegArray,
			ix_VexExpression, bias, data_VexExpression);
}
jobject create_StmStore(JNIEnv * jenv, jobject end_VexEndnessType,
		jobject addr_VexExpression, jobject data_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmStore;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			end_VexEndnessType, addr_VexExpression, data_VexExpression);
}
jobject create_StmStoreG(JNIEnv * jenv, jobject endness_VexEndnessType,
		jobject addr_VexExpression, jobject data_VexExpression,
		jobject guard_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmStoreG;");
	jmethodID constructor =
			(*jenv)->GetMethodID(jenv, target_class, "<init>",
					"(Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor,
			endness_VexEndnessType, addr_VexExpression, data_VexExpression,
			guard_VexExpression);
}
jobject create_StmWrTmp(JNIEnv * jenv, jint tmp_unsigned,
		jobject data_VexExpression) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/statements/StmWrTmp;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(ILca/mcgill/sis/dmas/kam1n0/vex/VexExpression;)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, tmp_unsigned,
			data_VexExpression);
}
jobject create_IRRegArray(JNIEnv * jenv, jint base,
		jobject type_VexVariableType, jint numElements) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/variable/IRRegArray;");
	jmethodID constructor = (*jenv)->GetMethodID(jenv, target_class, "<init>",
			"(ILca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexVariableType;I)V");
	return (*jenv)->NewObject(jenv, target_class, constructor, base,
			type_VexVariableType, numElements);
}
jobject create_enum_StmDirtyEffect(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/StmDirtyEffect;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/StmDirtyEffect;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_StmLoadGType(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/StmLoadGType;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/StmLoadGType;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_VexConstantType(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexConstantType;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexConstantType;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_VexEndnessType(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexEndnessType;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_VexExpressionType(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexExpressionType;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexExpressionType;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_VexJumpKind(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexJumpKind;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexJumpKind;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_VexOperationType(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexOperationType;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexOperationType;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_VexStatementType(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexStatementType;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexStatementType;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}
jobject create_enum_VexVariableType(JNIEnv * jenv, jint index) {
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexVariableType;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "fromInteger",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexVariableType;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, index);
}

//end of generated code
jclass array_class;
jmethodID array_add;
jmethodID array_create;

jclass vex_bb_class;
jfieldID vex_bb_types;
jfieldID vex_bb_statements;
jfieldID vex_bb_jmpKind;
jfieldID vex_bb_ipOffset;

void jni_init(JNIEnv * jenv) {
	array_class = (*jenv)->FindClass(jenv, "java/util/ArrayList");
	array_add = (*jenv)->GetMethodID(jenv, array_class, "add",
			"(Ljava/lang/Object;)Z");
	array_create = (*jenv)->GetMethodID(jenv, array_class, "<init>", "()V");

	vex_bb_class = (*jenv)->FindClass(jenv,
			"ca/mcgill/sis/dmas/kam1n0/vex/VEXIRBB");
	vex_bb_types = (*jenv)->GetFieldID(jenv, vex_bb_class, "types",
			"Ljava/util/ArrayList;");
	vex_bb_statements = (*jenv)->GetFieldID(jenv, vex_bb_class, "statements",
			"Ljava/util/ArrayList;");
	vex_bb_jmpKind = (*jenv)->GetFieldID(jenv, vex_bb_class, "jmpKind",
			"Lca/mcgill/sis/dmas/kam1n0/vex/enumeration/VexJumpKind;");
	vex_bb_ipOffset = (*jenv)->GetFieldID(jenv, vex_bb_class, "offsetsIP", "I");
}

jobject createList(JNIEnv * jenv) {
	return (*jenv)->NewObject(jenv, array_class, array_create);
}

void addToList(JNIEnv * jenv, jobject array_list, jobject object_to_add) {
	(*jenv)->CallVoidMethod(jenv, array_list, array_add, object_to_add);
}

jobject create_operation(JNIEnv * jenv, IROp op) {
#ifdef __debug_kam1n0__
	printf("creating operation\n");
#endif
	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/VexOperation;");

	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "createOperation",
			"(I)Lca/mcgill/sis/dmas/kam1n0/vex/VexOperation;");
	return (*jenv)->CallStaticObjectMethod(jenv, target_class,
			java_static_method, (unsigned int) op);
}

jobject create_constant(JNIEnv * jenv, IRConst * constVal) {

#ifdef __debug_kam1n0__
	printf("creating constant tag %x\n", constVal->tag);
#endif

	jclass target_class = (*jenv)->FindClass(jenv,
			"Lca/mcgill/sis/dmas/kam1n0/vex/VexConstant;");
	jmethodID java_static_method = (*jenv)->GetStaticMethodID(jenv,
			target_class, "createVexConstant",
			"(ILjava/lang/String;)Lca/mcgill/sis/dmas/kam1n0/vex/VexConstant;");

	char buffer[16];

	union {
		ULong i64;
		Double f64;
		UInt i32;
		Float f32;
	} u;

	switch (constVal->tag) {
	case Ico_U1:
		sprintf(buffer, "%d", constVal->Ico.U1);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_U8:
		sprintf(buffer, "0x%x", constVal->Ico.U8);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_U16:
		sprintf(buffer, "0x%x", constVal->Ico.U16);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_U32:
		sprintf(buffer, "0x%x", constVal->Ico.U32);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_U64:
		sprintf(buffer, "0x%x", constVal->Ico.U64);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_F32:
		u.f32 = constVal->Ico.F32;
		sprintf(buffer, "0x%x", u.i32);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_F32i:
		sprintf(buffer, "0x%x", constVal->Ico.F32i);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_F64:
		u.f64 = constVal->Ico.F64;
		sprintf(buffer, "0x%llx", u.i64);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_F64i: {
		sprintf(buffer, "0x%llx", constVal->Ico.F64i);

		jobject str_buffer = (*jenv)->NewStringUTF(jenv, buffer);

		jobject cons = (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag, str_buffer);

		return cons;
	}
	case Ico_V128:
		sprintf(buffer, "0x%04x", (UInt) constVal->Ico.V128);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	case Ico_V256:
		sprintf(buffer, "0x%08x", constVal->Ico.V256);
		return (*jenv)->CallStaticObjectMethod(jenv, target_class,
				java_static_method, constVal->tag,
				(*jenv)->NewStringUTF(jenv, buffer));
	default:
		return NULL;
	}
}

jobject createExpression(JNIEnv * jenv, IRExpr* expr) {
#ifdef __debug_kam1n0__
	printf("creating expression tag %x\n", expr->tag);
#endif
	switch (expr->tag) {
	case Iex_Binder:
		return create_ExBinder(jenv, expr->Iex.Binder.binder);
	case Iex_Get:
		return create_ExGet(jenv, expr->Iex.Get.offset,
				create_enum_VexVariableType(jenv, expr->Iex.Get.ty));
	case Iex_GetI:
		return create_ExGetI(jenv,
				create_IRRegArray(jenv, expr->Iex.GetI.descr->base,
						create_enum_VexVariableType(jenv,
								expr->Iex.GetI.descr->elemTy),
						expr->Iex.GetI.descr->nElems),
				createExpression(jenv, expr->Iex.GetI.ix), expr->Iex.GetI.bias);
	case Iex_RdTmp:
		return create_ExRdTmp(jenv, expr->Iex.RdTmp.tmp);
	case Iex_Qop:
		return create_ExQop(jenv,
				create_operation(jenv, expr->Iex.Qop.details->op),
				createExpression(jenv, expr->Iex.Qop.details->arg1),
				createExpression(jenv, expr->Iex.Qop.details->arg2),
				createExpression(jenv, expr->Iex.Qop.details->arg3),
				createExpression(jenv, expr->Iex.Qop.details->arg4));
	case Iex_Triop:
		return create_ExTriop(jenv,
				create_operation(jenv, expr->Iex.Triop.details->op),
				createExpression(jenv, expr->Iex.Triop.details->arg1),
				createExpression(jenv, expr->Iex.Triop.details->arg2),
				createExpression(jenv, expr->Iex.Triop.details->arg3));
	case Iex_Binop:
		return create_ExBinop(jenv,
				create_operation(jenv, (int) expr->Iex.Binop.op),
				createExpression(jenv, expr->Iex.Binop.arg1),
				createExpression(jenv, expr->Iex.Binop.arg2));
	case Iex_Unop:
		return create_ExUnop(jenv, create_operation(jenv, expr->Iex.Unop.op),
				createExpression(jenv, expr->Iex.Unop.arg));
	case Iex_Load:
		return create_ExLoad(jenv,
				create_enum_VexEndnessType(jenv, expr->Iex.Load.end),
				create_enum_VexVariableType(jenv, expr->Iex.Load.ty),
				createExpression(jenv, expr->Iex.Load.addr));
	case Iex_Const:
		return create_ExConst(jenv,
				create_constant(jenv, expr->Iex.Const.con));
	case Iex_ITE:
		return create_ExITE(jenv, createExpression(jenv, expr->Iex.ITE.cond),
				createExpression(jenv, expr->Iex.ITE.iftrue),
				createExpression(jenv, expr->Iex.ITE.iffalse));
	case Iex_CCall: {

		jobject ls_exp = createList(jenv);
		for (int i = 0; expr->Iex.CCall.args[i] != NULL; i++) {
			IRExpr* arg = expr->Iex.CCall.args[i];
			jobject exp = createExpression(jenv, arg);
			addToList(jenv, ls_exp, exp);
		}
		return create_ExCCall(jenv,
				create_VexCall(jenv, expr->Iex.CCall.cee->regparms,
						(*jenv)->NewStringUTF(jenv, expr->Iex.CCall.cee->name),
						(unsigned long long int) expr->Iex.CCall.cee->addr,
						(unsigned int) expr->Iex.CCall.cee->mcx_mask),
				create_enum_VexVariableType(jenv, expr->Iex.CCall.retty),
				ls_exp);
	}
	case Iex_VECRET:
		return create_ExVECRET(jenv);
	case Iex_BBPTR: {
		jobject result = create_ExBBPTR(jenv);
		return result;
	}
	default:
		return NULL;
	}

}

jobject createStatement(JNIEnv * jenv, IRStmt * expr) {
	switch (expr->tag) {
	case Ist_NoOp:
		return create_StmNoOp(jenv);
	case Ist_IMark:
		return create_StmIMark(jenv, expr->Ist.IMark.addr, expr->Ist.IMark.len,
				expr->Ist.IMark.delta);
	case Ist_AbiHint:
		return create_StmAbiHint(jenv,
				createExpression(jenv, expr->Ist.AbiHint.base),
				expr->Ist.AbiHint.len,
				createExpression(jenv, expr->Ist.AbiHint.nia));
	case Ist_Put:
		return create_StmPut(jenv, expr->Ist.Put.offset,
				createExpression(jenv, expr->Ist.Put.data));
	case Ist_PutI:
		return create_StmPutI(jenv,
				create_IRRegArray(jenv, expr->Ist.PutI.details->descr->base,
						create_enum_VexVariableType(jenv,
								expr->Ist.PutI.details->descr->elemTy),
						expr->Ist.PutI.details->descr->nElems),
				createExpression(jenv, expr->Ist.PutI.details->ix),
				expr->Ist.PutI.details->bias,
				createExpression(jenv, expr->Ist.PutI.details->data));
	case Ist_WrTmp: {
		jobject data = createExpression(jenv, expr->Ist.WrTmp.data);
		return create_StmWrTmp(jenv, expr->Ist.WrTmp.tmp, data);
	}
	case Ist_Store:
		return create_StmStore(jenv,
				create_enum_VexEndnessType(jenv, expr->Ist.Store.end),
				createExpression(jenv, expr->Ist.Store.addr),
				createExpression(jenv, expr->Ist.Store.data));
	case Ist_LoadG:
		return create_StmLoadG(jenv,
				create_enum_VexEndnessType(jenv, expr->Ist.LoadG.details->end),
				create_enum_StmLoadGType(jenv, expr->Ist.LoadG.details->cvt),
				expr->Ist.LoadG.details->dst,
				createExpression(jenv, expr->Ist.LoadG.details->addr),
				createExpression(jenv, expr->Ist.LoadG.details->alt),
				createExpression(jenv, expr->Ist.LoadG.details->guard));
	case Ist_StoreG:
		return create_StmStoreG(jenv,
				create_enum_VexEndnessType(jenv, expr->Ist.StoreG.details->end),
				createExpression(jenv, expr->Ist.StoreG.details->addr),
				createExpression(jenv, expr->Ist.StoreG.details->data),
				createExpression(jenv, expr->Ist.StoreG.details->guard));
	case Ist_CAS: {

		jobject end = create_enum_VexEndnessType(jenv,
				expr->Ist.CAS.details->end);
		jobject exphi = NULL;
		jobject datahi = NULL;
		if (expr->Ist.CAS.details->expdHi)
			exphi = createExpression(jenv, expr->Ist.CAS.details->expdHi);
		if (expr->Ist.CAS.details->dataHi)
			datahi = createExpression(jenv, expr->Ist.CAS.details->dataHi);

		return create_StmCAS(jenv, expr->Ist.CAS.details->oldHi,
				expr->Ist.CAS.details->oldLo, end, exphi,
				createExpression(jenv, expr->Ist.CAS.details->expdLo), datahi,
				createExpression(jenv, expr->Ist.CAS.details->dataLo), 
				createExpression(jenv, expr->Ist.CAS.details->addr));
	}
	case Ist_LLSC:
	    if(expr->Ist.LLSC.storedata == NULL)
			return create_StmLLSC(jenv,
				create_enum_VexEndnessType(jenv, expr->Ist.LLSC.end),
				expr->Ist.LLSC.result,
				createExpression(jenv, expr->Ist.LLSC.addr),
				NULL);
		else
		return create_StmLLSC(jenv,
				create_enum_VexEndnessType(jenv, expr->Ist.LLSC.end),
				expr->Ist.LLSC.result,
				createExpression(jenv, expr->Ist.LLSC.addr),
				createExpression(jenv, expr->Ist.LLSC.storedata));
	case Ist_Dirty: {
		
		//ppIRDirty(expr->Ist.Dirty.details);
		//printf("\n");
		
		jobject ls_exp = createList(jenv);
		for (int i = 0; expr->Ist.Dirty.details->args[i] != NULL; i++) {
			IRExpr* arg = expr->Ist.Dirty.details->args[i];
			jobject exp = createExpression(jenv, arg);
			addToList(jenv, ls_exp, exp);
		}

		jobject ls = createList(jenv);
		for (int i = 0; i < expr->Ist.Dirty.details->nFxState; i++) {
			addToList(jenv, ls,
					create_StmDirtyFxStat(jenv,
							create_enum_StmDirtyEffect(jenv,
									expr->Ist.Dirty.details->fxState[i].fx),
							expr->Ist.Dirty.details->fxState[i].offset,
							expr->Ist.Dirty.details->fxState[i].size,
							expr->Ist.Dirty.details->fxState[i].nRepeats,
							expr->Ist.Dirty.details->fxState[i].repeatLen));
		}

		jobject vexCall = create_VexCall(jenv,
				expr->Ist.Dirty.details->cee->regparms,
				(*jenv)->NewStringUTF(jenv, expr->Ist.Dirty.details->cee->name),
				(unsigned long long int) expr->Ist.Dirty.details->cee->addr,
				expr->Ist.Dirty.details->cee->mcx_mask);

		jobject effect = create_enum_StmDirtyEffect(jenv,
				expr->Ist.Dirty.details->mFx);
		jobject guard = createExpression(jenv, expr->Ist.Dirty.details->guard);

		jobject maddr = NULL;
		if (expr->Ist.Dirty.details->mFx != Ifx_None) {
			createExpression(jenv, expr->Ist.Dirty.details->mAddr);
		}

		return create_StmDirty(jenv, vexCall, guard, ls_exp, //
				expr->Ist.Dirty.details->tmp, //
				effect, maddr, expr->Ist.Dirty.details->mSize, //
				ls);
	}
	case Ist_MBE:
		return create_StmMBE(jenv,
				expr->Ist.MBE.event == Imbe_Fence ? True : False);
	case Ist_Exit:
		return create_StmExit(jenv,
				createExpression(jenv, expr->Ist.Exit.guard),
				create_constant(jenv, expr->Ist.Exit.dst),
				create_enum_VexJumpKind(jenv, expr->Ist.Exit.jk),
				expr->Ist.Exit.offsIP);
	default:
		return NULL;
	}
}

void populate_env(JNIEnv * jenv, jobject caller, IRTypeEnv* env) {

	jobject type_list = (*jenv)->GetObjectField(jenv, caller, vex_bb_types);

	for (int i = 0; i < env->types_used; ++i) {
		jobject vex_type = create_enum_VexVariableType(jenv,
				(unsigned int) env->types[i]);
		if (vex_type == NULL) {
			printf("Cannot create vex_type\n");
			continue;
		}
		(*jenv)->CallVoidMethod(jenv, type_list, array_add, vex_type);
	}
}

void populate_stm(JNIEnv * jenv, jobject caller, IRSB * irsb) {

	jobject stm_list = (*jenv)->GetObjectField(jenv, caller, vex_bb_statements);

	for (int i = 0; i < irsb->stmts_used; ++i) {

#ifdef __debug_kam1n0__
		printf("creating statement %0x\n", irsb->stmts[i]->tag);
		ppIRStmt(irsb->stmts[i]);
		printf("\n");
#endif

		jobject vex_stm = createStatement(jenv, irsb->stmts[i]);
		if (vex_stm == NULL) {
			printf("Cannot create vex_stm\n");
			continue;
		}
		(*jenv)->CallVoidMethod(jenv, stm_list, array_add, vex_stm);
#ifdef __debug_kam1n0__		
		printf("\n");
#endif
	}

	(*jenv)->SetIntField(jenv, caller, vex_bb_ipOffset, irsb->offsIP);
	(*jenv)->SetObjectField(jenv, caller, vex_bb_jmpKind,
			create_enum_VexJumpKind(jenv, irsb->jumpkind));

}

JNIEXPORT void Java_ca_mcgill_sis_dmas_kam1n0_vex_VEXIRBB_translateToVexIR(
		JNIEnv * env, jobject caller, //
		jint arch, //
		jint hwcaps, //
		jint endness, //
		jint ppc_icache_line_szB, //
		jint ppc_dcbz_szB, //
		jint ppc_dczl_szB, //
		jint arm64_dMinLin_lg2_szB, //
		jint arm64_iMinLine_lg2_szB, //
		jint hwcache_info_num_levels, //
		jint hwcache_info_num_caches, //
		jint hwcache_info_caches, //
		jboolean hwcache_info_icaches_maintain_choherence, //
		jint info_x86_cr, jbyteArray bytes, jlong address, jint num_inst) {

//printf("Hello word!\n");

	//printf("%x\n", address);

	jni_init(env);

	vex_init();

	VexArchInfo info;
	info.hwcaps = hwcaps;
	info.endness = endness;
	info.ppc_icache_line_szB = ppc_icache_line_szB;
	info.ppc_dcbz_szB = ppc_dcbz_szB;
	info.ppc_dcbzl_szB = ppc_dczl_szB;
	info.arm64_dMinLine_lg2_szB = arm64_dMinLin_lg2_szB;
	info.arm64_iMinLine_lg2_szB = arm64_iMinLine_lg2_szB;
	info.hwcache_info.num_levels = hwcache_info_num_levels;
	info.hwcache_info.num_caches = hwcache_info_num_caches;
	info.hwcache_info.caches = NULL;
	info.hwcache_info.icaches_maintain_coherence =
			hwcache_info_icaches_maintain_choherence;
	info.x86_cr0 = info_x86_cr;

#ifdef __debug_kam1n0__
	printf("x86_cr0 %x\n", info.x86_cr0);
	printf("arch2 %d\n", arch);
	printf("endness %x\n", endness);
#endif
	int len = (*env)->GetArrayLength(env, bytes);
	unsigned char buf[len];
	(*env)->GetByteArrayRegion(env, bytes, 0, len, buf);

#ifdef __debug_kam1n0__
	for (int i = 0; i < len; ++i)
		printf("%x\n", buf[i]);
#endif

	IRSB * result = vex_block_inst(arch, info, buf, address, num_inst);
#ifdef __debug_kam1n0__
	ppIRSB(result);
#endif
	populate_env(env, caller, result->tyenv);
	populate_stm(env, caller, result);
	
	// populate `next` expression
	jclass cls = (*env)->GetObjectClass(env, caller);
	jint fid = (*env)->GetFieldID(env, cls, "next", "Lca/mcgill/sis/dmas/kam1n0/vex/VexExpression;");
	(*env)->SetObjectField(env, caller, fid, createExpression(env, result->next));
}

// these are problematic because we need to link with vex statically to use them, I think
extern VexControl vex_control;
extern Bool vex_initdone;

// the last thrown error
char *last_error;

//======================================================================
//
// Globals
//
//======================================================================

// Some info required for translation
VexArchInfo vai_host;
VexGuestExtents vge;
VexTranslateArgs vta;
VexTranslateResult vtr;
VexAbiInfo vbi;
VexControl vc;

// Global for saving the intermediate results of translation from
// within the callback (instrument1)
IRSB *irbb_current = NULL;

//======================================================================
//
// Functions needed for the VEX translation
//
//======================================================================

static __attribute((noreturn)) void failure_exit(void) {
// log error
	// exit(1); no exit
	printf("Error exiting.. \n");
	fflush(stdout); 
}

static void log_bytes(const HChar* bytes, SizeT nbytes) {
// log bytes
	SizeT i;
	for (i = 0; i < nbytes - 3; i += 4)
		; //printf("%c%c%c%c", bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
	for (; i < nbytes; i++)
		; //printf("%c", bytes[i]);
}

static Bool chase_into_ok(void *closureV, Addr addr64) {
	return False;
}

// TODO: figure out what this is for
static UInt needs_self_check(void *callback_opaque,
		VexRegisterUpdates* pxControl, const VexGuestExtents *guest_extents) {
	return 0;
}

static void *dispatch(void) {
	return NULL;
}

//----------------------------------------------------------------------
// This is where we copy out the IRSB
//----------------------------------------------------------------------
static IRSB *instrument1(void *callback_opaque, IRSB *irbb,
		const VexGuestLayout *vgl, const VexGuestExtents *vge,
		const VexArchInfo *vae, IRType gWordTy, IRType hWordTy) {

	assert(irbb);

//irbb_current = (IRSB *)vx_dopyIRSB(irbb);
	irbb_current = deepCopyIRSB(irbb);

//if (debug_on)
// ppIRSB(irbb);
	return irbb;
}

//----------------------------------------------------------------------
// Initializes VEX
// It must be called before using VEX for translation to Valgrind IR
//----------------------------------------------------------------------
void vex_init() {
	static int initialized = 0;
//printf("Initializing VEX.\n");

	if (initialized || vex_initdone) {
//printf("VEX already initialized.\n");
		return;
	}
	initialized = 1;

//
// Initialize VEX
//
	LibVEX_default_VexControl(&vc);

	vc.iropt_verbosity = 0;
	vc.iropt_level = 0;    // No optimization by default
//vc.iropt_level                  = 2;
//vc.iropt_precise_memory_exns    = False;
	vc.iropt_unroll_thresh = 0;
	vc.guest_max_insns = 1;    // By default, we vex 1 instruction at a time
	vc.guest_chase_thresh = 0;

//printf("Calling LibVEX_Init()....\n");
	LibVEX_Init(&failure_exit, &log_bytes, 0,              // Debug level
			&vc);
	//printf("LibVEX_Init() done....\n");

	LibVEX_default_VexArchInfo(&vai_host);
	LibVEX_default_VexAbiInfo(&vbi);

	vai_host.endness = VexEndnessLE; // TODO: Don't assume this

// various settings to make stuff work
// ... former is set to 'unspecified', but gets set in vex_inst for archs which care
// ... the latter two are for dealing with gs and fs in VEX
	vbi.guest_stack_redzone_size = 0;
	vbi.guest_amd64_assume_fs_is_const = True;
	vbi.guest_amd64_assume_gs_is_const = True;

//------------------------------------
// options for instruction translation

//
// Architecture info
//
	vta.arch_guest = VexArch_INVALID; // to be assigned later
	vta.archinfo_host = vai_host;
#if __amd64__
	vta.arch_host = VexArchAMD64;
#elif __i386__
	vta.arch_host = VexArchX86;
#elif __arm__
	vta.arch_host = VexArchARM;
#elif __aarch64__
	vta.arch_host = VexArchARM64;
#else
#error "Unsupported host arch"
#endif

//
// The actual stuff to vex
//
	vta.guest_bytes = NULL;             // Set in vex_insts
	vta.guest_bytes_addr = 0;                // Set in vex_insts

//
// callbacks
//
	vta.callback_opaque = NULL; // Used by chase_into_ok, but never actually called
	vta.chase_into_ok = chase_into_ok;    // Always returns false
	vta.preamble_function = NULL;
	vta.instrument1 = instrument1; // Callback we defined to help us save the IR
	vta.instrument2 = NULL;
	vta.finaltidy = NULL;
	vta.needs_self_check = needs_self_check;

#if 0
	vta.dispatch_assisted = (void *)dispatch; // Not used
	vta.dispatch_unassisted = (void *)dispatch;// Not used
#else
	vta.disp_cp_chain_me_to_slowEP = (void *) dispatch; // Not used
	vta.disp_cp_chain_me_to_fastEP = (void *) dispatch; // Not used
	vta.disp_cp_xindir = (void *) dispatch; // Not used
	vta.disp_cp_xassisted = (void *) dispatch; // Not used
#endif

	vta.guest_extents = &vge;
	vta.host_bytes = NULL;           // Buffer for storing the output binary
	vta.host_bytes_size = 0;
	vta.host_bytes_used = NULL;
// doesn't exist? vta.do_self_check       = False;
#ifdef __debug_kam1n0__
	vta.traceflags = -1;                // Debug verbosity
#else
	vta.traceflags          = 0;                // Debug verbosity
#endif
}

// Prepare the VexArchInfo struct
static void vex_prepare_vai(VexArch arch, VexArchInfo *vai) {
	switch (arch) {
	case VexArchX86:
		vai->hwcaps = VEX_HWCAPS_X86_MMXEXT |
		VEX_HWCAPS_X86_SSE1 |
		VEX_HWCAPS_X86_SSE2 |
		VEX_HWCAPS_X86_SSE3 |
		VEX_HWCAPS_X86_LZCNT;
		break;
	case VexArchAMD64:
		vai->hwcaps = VEX_HWCAPS_AMD64_SSE3 |
		VEX_HWCAPS_AMD64_CX16 |
		VEX_HWCAPS_AMD64_LZCNT |
		VEX_HWCAPS_AMD64_AVX |
		VEX_HWCAPS_AMD64_RDTSCP |
		VEX_HWCAPS_AMD64_BMI |
		VEX_HWCAPS_AMD64_AVX2;
		break;
	case VexArchARM:
		vai->hwcaps = 7;
		break;
	case VexArchARM64:
		vai->hwcaps = 0;
		vai->arm64_dMinLine_lg2_szB = 6;
		vai->arm64_iMinLine_lg2_szB = 6;
		break;
	case VexArchPPC32:
		vai->hwcaps = VEX_HWCAPS_PPC32_F |
		VEX_HWCAPS_PPC32_V |
		VEX_HWCAPS_PPC32_FX |
		VEX_HWCAPS_PPC32_GX |
		VEX_HWCAPS_PPC32_VX |
		VEX_HWCAPS_PPC32_DFP |
		VEX_HWCAPS_PPC32_ISA2_07;
		vai->ppc_icache_line_szB = 32; // unsure if correct
		break;
	case VexArchPPC64:
		vai->hwcaps = VEX_HWCAPS_PPC64_V |
		VEX_HWCAPS_PPC64_FX |
		VEX_HWCAPS_PPC64_GX |
		VEX_HWCAPS_PPC64_VX |
		VEX_HWCAPS_PPC64_DFP |
		VEX_HWCAPS_PPC64_ISA2_07;
		vai->ppc_icache_line_szB = 64; // unsure if correct
		break;
	case VexArchS390X:
		vai->hwcaps = 0;
		break;
	case VexArchMIPS32:
		vai->hwcaps = 0x00010000;
		break;
	case VexArchMIPS64:
		vai->hwcaps = 0;
		break;
	default:
		printf("Invalid arch in vex_prepare_vai.\n");
		break;
	}
}

// Prepare the VexAbiInfo
static void vex_prepare_vbi(VexArch arch, VexAbiInfo *vbi) {
// only setting the guest_stack_redzone_size for now
// this attribute is only specified by the PPC64 and AMD64 ABIs

	vbi->guest_stack_redzone_size = 0;

	switch (arch) {
	case VexArchAMD64:
		vbi->guest_stack_redzone_size = 128;
		break;
	case VexArchPPC64:
		vbi->guest_stack_redzone_size = 288;
		break;
	default:
		break;
	}
}

//----------------------------------------------------------------------
// Translate 1 instruction to VEX IR.
//----------------------------------------------------------------------
static IRSB *vex_inst(VexArch guest, VexArchInfo archinfo,
		unsigned char *insn_start, unsigned long long insn_addr, int max_insns) {
	vex_prepare_vai(guest, &archinfo);
	vex_prepare_vbi(guest, &vbi);

//printf("Guest arch: %d\n", guest);
//printf("Guest arch hwcaps: %08x\n", archinfo.hwcaps);
//vta.traceflags = 0xffffffff;

	vta.archinfo_guest = archinfo;
	vta.arch_guest = guest;
	vta.abiinfo_both = vbi; // Set the vbi value

	vta.guest_bytes = (UChar *) (insn_start); // Ptr to actual bytes of start of instruction
	vta.guest_bytes_addr = (Addr64) (insn_addr);

//printf("Setting VEX max instructions...\n");
//printf("... old: %d\n", vex_control.guest_max_insns);
	vex_control.guest_max_insns = max_insns; // By default, we vex 1 instruction at a time
//printf("... new: %d\n", vex_control.guest_max_insns);

// Do the actual translation
	vtr = LibVEX_Translate(&vta);
//printf("Translated!\n");

	assert(irbb_current);
	return irbb_current;
}

unsigned int vex_count_instructions(VexArch guest, VexArchInfo archinfo,
		unsigned char *instructions, unsigned long long block_addr,
		unsigned int num_bytes, int basic_only) {
//printf("Counting instructions in %d bytes starting at 0x%x, basic %d\n",
//		num_bytes, block_addr, basic_only);

	unsigned int count = 0;
	unsigned int processed = 0;
	int per_lift = basic_only ? 3 : 1;

	while (processed < num_bytes && count < 99) {
//printf("Next byte: %02x\n", instructions[processed]);
		IRSB *sb = vex_inst(guest, archinfo, instructions + processed,
				block_addr + processed, per_lift);

		if (vge.len[0] == 0 || sb == NULL) {
			if (sb) {
				// Block translated, got length of zero: first instruction is NoDecode
				count += 1;
			}
			printf(
					"Something went wrong in IR translation at position %x of addr %x in vex_count_instructions.\n",
					processed, block_addr);
			break;
		}

		IRStmt *first_imark = NULL;
		for (int i = 0; i < sb->stmts_used; i++) {
			if (sb->stmts[i]->tag == Ist_IMark) {
				first_imark = sb->stmts[i];
				break;
			}
		}
		assert(first_imark);

		if (basic_only) {
			if (vtr.n_guest_instrs < 3) {
				// Found an exit!!
				if (processed + first_imark->Ist.IMark.len >= num_bytes) {
					// edge case: This is the first run through this loop (processed == 0) and
					// the first instruction is long enough to fill up the byte quota.
					count += 1;
					processed += first_imark->Ist.IMark.len;
					//printf("Processed %d bytes\n", processed);
					break;
				}
				count += vtr.n_guest_instrs;
				processed += vge.len[0];
				//printf("Processed %d bytes\n", processed);
				break;
			}
		}

		processed += first_imark->Ist.IMark.len;
//printf("Processed %d bytes\n", processed);

		assert(vge.n_used == 1);
		count++;
	}

// count is one too high if the number of processed bytes is greater than num_bytes
	if (processed > num_bytes) {
		count--;
	}

//printf("... found %d instructions!\n", count);
	return count;
}

IRSB *vex_block_bytes(VexArch guest, VexArchInfo archinfo,
		unsigned char *instructions, unsigned long long block_addr,
		unsigned int num_bytes, int basic_only) {
	IRSB *sb = NULL;

//	try{
	unsigned int count = vex_count_instructions(guest, archinfo, instructions, block_addr, num_bytes, basic_only);
	sb = vex_block_inst(guest, archinfo, instructions, block_addr, count);
// this is a workaround. Basically, on MIPS, leaving this (the second translation of the same crap)
// out leads to exits being dropped in some IRSBs
	//sb = vex_block_inst(guest, archinfo, instructions, block_addr, count);
	if (vge.len[0] != num_bytes)
	{
		printf("vex_block_bytes: only translated %d bytes out of %d in block_addr %x\n", vge.len[0], num_bytes, block_addr);
	}
//assert(vge.len[0] == num_bytes);
//}
//catch (VEXError)
//{
//	last_error = E4C_EXCEPTION.message;
//}

	return sb;
}

IRSB *vex_block_inst(VexArch guest, VexArchInfo archinfo,
		unsigned char *instructions, unsigned long long block_addr,
		unsigned int num_inst) {
//printf("Translating %d instructions starting at 0x%x\n", num_inst, block_addr);

	if (num_inst == 0) {
//printf(	"vex_block_inst: asked to create IRSB with 0 instructions, at block_addr %x\n", block_addr);
		return NULL;
	} else if (num_inst > 99) {
 printf("vex_block_inst: maximum instruction count is 99. Input %d\n", num_inst);
		num_inst = 99;
	}

	IRSB *fullblock = NULL;

//	try{
	fullblock = vex_inst(guest, archinfo, instructions, block_addr, num_inst);
	assert(vge.n_used == 1);
//}
//catch (VEXError)
//{
//	last_error = E4C_EXCEPTION.message;
//}

	return fullblock;
}

int main() {

	printf("Hello word!\n");

//jni_init(env);

	printf("%d \n", sizeof(void*));
	printf("%d\n", sizeof(HWord));

	vex_init();

	VexArchInfo info;
	info.hwcaps = 0;
	info.endness = 0x601;
	info.ppc_icache_line_szB = 0;
	info.ppc_dcbz_szB = 0;
	info.ppc_dcbzl_szB = 0;
	info.arm64_dMinLine_lg2_szB = 0;
	info.arm64_iMinLine_lg2_szB = 0;
	info.hwcache_info.num_levels = 0;
	info.hwcache_info.num_caches = 0;
	info.hwcache_info.caches = NULL;
	info.hwcache_info.icaches_maintain_coherence = True;
	info.x86_cr0 = 0xffffffff;

	VexArch arch = VexArchAMD64;

	unsigned char instructions[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
	IRSB * result = vex_block_inst(arch, info, instructions, 0x400400, 5);
	ppIRSB(result);

}
