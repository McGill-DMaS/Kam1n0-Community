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
package ca.mcgill.sis.dmas.kam1n0.vex;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexExpressionType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;
import ca.mcgill.sis.dmas.kam1n0.vex.expression.*;
import ca.mcgill.sis.dmas.kam1n0.vex.operation.VexOperationUtils.TypeInformation;

import java.util.List;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class VexExpression {

	private static Logger logger = LoggerFactory.getLogger(VexExpression.class);

	public VexExpressionType tag;

	public ComputationNode getNode(ComputationGraph graph, long ina) {
		logger.error("Not implemented expression interpretator for expression type: {}. Addr 0x{}", tag,
				Long.toHexString(ina));
		// throw new NotImplementedException();
		return null;
	}

	public abstract void updateTmpOffset(int newOffset);
	
	public abstract String toStr(VexToStrState state);

	@JsonIgnore
	public TypeInformation getTypeInformation(List<VexVariableType> tmpTypes) {
		switch (this.tag) {
		case Iex_Load: {
			VexVariableType varType = ((ExLoad) this).type;// e->Iex.Load.ty;
			TypeInformation information = new TypeInformation();
			information.argType.add(varType);
			information.outputType = varType;
			return information;
		}
		case Iex_Get:
		// return e->Iex.Get.ty;
		{
			VexVariableType varType = ((ExGet) this).type;
			TypeInformation information = new TypeInformation();
			information.argType.add(varType);
			information.outputType = varType;
			return information;
		}
		case Iex_GetI:
		// return e->Iex.GetI.descr->elemTy;
		{
			VexVariableType varType = ((ExGetI) this).descr.type;
			TypeInformation information = new TypeInformation();
			information.argType.add(varType);
			information.outputType = varType;
			return information;
		}
		case Iex_RdTmp:
		// return typeOfIRTemp(tyenv, e->Iex.RdTmp.tmp);
		{
			VexVariableType varType = tmpTypes.get(((ExRdTmp) this).tmp_unsigned);
			TypeInformation information = new TypeInformation();
			information.argType.add(varType);
			information.outputType = varType;
			return information;
		}
		case Iex_Const:
		// return typeOfIRConst(e->Iex.Const.con);
		{
			VexVariableType varType = ((ExConst) this).constant.type.toVariableType();
			TypeInformation information = new TypeInformation();
			information.argType.add(varType);
			information.outputType = varType;
			return information;
		}
		case Iex_Qop:
		// typeOfPrimop(e->Iex.Qop.details->op, &t_dst, &t_arg1, &t_arg2,
		// &t_arg3, &t_arg4);
		// return t_dst;
		{
			return ((ExQop) this).operation.tag.getTypeInfo();
		}
		case Iex_Triop:
		// typeOfPrimop(e->Iex.Triop.details->op,&t_dst, &t_arg1, &t_arg2,
		// &t_arg3, &t_arg4);
		// return t_dst;
		{
			return ((ExTriop) this).operation.tag.getTypeInfo();
		}
		case Iex_Binop:
		// typeOfPrimop(e->Iex.Binop.op, &t_dst, &t_arg1, &t_arg2, &t_arg3,
		// &t_arg4);
		// return t_dst;
		{
			return ((ExBinop) this).operation.tag.getTypeInfo();
		}
		case Iex_Unop:
		// typeOfPrimop(e->Iex.Unop.op, &t_dst, &t_arg1, &t_arg2, &t_arg3,
		// &t_arg4);
		// return t_dst;
		{
			return ((ExUnop) this).operation.tag.getTypeInfo();
		}
		case Iex_CCall:
		// return e->Iex.CCall.retty;
		{
			ExCCall ccall = ((ExCCall) this);
			VexVariableType varType = ccall.type;
			TypeInformation information = new TypeInformation();
			ccall.args.forEach(arg -> {
				information.argType.add(arg.getTypeInformation(tmpTypes).outputType);
			});
			information.outputType = varType;
			return information;
		}
		case Iex_ITE:
		// e = e->Iex.ITE.iffalse;
		/* return typeOfIRExpr(tyenv, e->Iex.ITE.iffalse); */
		{
			return ((ExITE) this).iffalse.getTypeInformation(tmpTypes);
		}
		case Iex_Binder:
			logger.error("typeOfIRExpr: Binder is not a valid expression");
		case Iex_VECRET:
			logger.error("typeOfIRExpr: VECRET is not a valid expression");
		case Iex_BBPTR:
			logger.error("typeOfIRExpr: BBPTR is not a valid expression");
		default:
			logger.error("typeOfIRExpr {} is not a valid expression", this);
		}
		return null;
	}

}
