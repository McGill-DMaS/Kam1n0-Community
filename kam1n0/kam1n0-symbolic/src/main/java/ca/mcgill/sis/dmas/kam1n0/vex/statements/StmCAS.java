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
package ca.mcgill.sis.dmas.kam1n0.vex.statements;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import ca.mcgill.sis.dmas.kam1n0.graph.ComputationGraph;
import ca.mcgill.sis.dmas.kam1n0.graph.ComputationNode;
import ca.mcgill.sis.dmas.kam1n0.vex.VexArchitecture;
import ca.mcgill.sis.dmas.kam1n0.vex.VexExpression;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement;
import ca.mcgill.sis.dmas.kam1n0.vex.VexStatement.VexToStrState;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexEndnessType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexOperationType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexStatementType;
import ca.mcgill.sis.dmas.kam1n0.vex.enumeration.VexVariableType;

public class StmCAS extends VexStatement {
	public int oldHi_unsigned;
	public int oldLo_unsigned;
	public VexEndnessType endness;
	public VexExpression expdHi;
	public VexExpression expdLo;
	public VexExpression dataHi;
	public VexExpression dataLow;
	public VexExpression addr;

	public StmCAS(@JsonProperty("oldHi_unsigned") int oldHi_unsigned,
			@JsonProperty("oldLo_unsigned") int oldLo_unsigned, @JsonProperty("endness") VexEndnessType endness,
			@JsonProperty("expdHi") VexExpression expdHi, @JsonProperty("expdLo") VexExpression expdLo,
			@JsonProperty("dataHi") VexExpression dataHi, @JsonProperty("dataLow") VexExpression dataLow,
			@JsonProperty("dataLow") VexExpression addr) {
		super();
		this.oldHi_unsigned = oldHi_unsigned;
		this.oldLo_unsigned = oldLo_unsigned;
		this.endness = endness;
		this.expdHi = expdHi;
		this.expdLo = expdLo;
		this.dataHi = dataHi;
		this.dataLow = dataLow;
		this.tag = VexStatementType.Ist_CAS;
		this.addr = addr;
	}

	@JsonIgnore
	private boolean updatedTmp = false;

	@Override
	public void updateTmpOffset(int newOffset) {
		if (expdHi != null)
			expdHi.updateTmpOffset(newOffset);
		if (expdLo != null)
			expdLo.updateTmpOffset(newOffset);
		if (dataHi != null)
			dataHi.updateTmpOffset(newOffset);
		if (dataLow != null)
			dataLow.updateTmpOffset(newOffset);
		if (addr != null)
			addr.updateTmpOffset(newOffset);

		if (!updatedTmp) {
			updatedTmp = true;
			oldHi_unsigned += newOffset;
			oldLo_unsigned += newOffset;
		}
	}

	@Override
	public ComputationNode translate(ComputationGraph graph) {
		if (expdHi != null && dataHi != null) {
			ComputationNode expdLoNode = expdLo.getNode(graph, ina);
			ComputationNode expdHiNode = expdHi.getNode(graph, ina);
			ComputationNode dataLowNode = dataLow.getNode(graph, ina);
			ComputationNode dataHiNode = dataHi.getNode(graph, ina);
			ComputationNode tmpLoNode = graph.getTmpVar(oldLo_unsigned);
			ComputationNode tmpHiNode = graph.getTmpVar(oldHi_unsigned);
			ComputationNode addrNode = addr.getNode(graph, ina);

			int readSize = dataLowNode.valType.outputType.numOfBit() + dataHiNode.valType.outputType.numOfBit();
			ComputationNode old_mem = graph.memory.readMem(ina, addrNode, VexVariableType.getIntType(readSize), endness,
					graph);
			VexOperationType opr_chop_lo = VexOperationType.Iop_32to16;
			VexOperationType opr_chop_hi = VexOperationType.Iop_32HIto16;
			switch (readSize) {
			case 16:
				opr_chop_lo = VexOperationType.Iop_16to8;
				opr_chop_hi = VexOperationType.Iop_16HIto8;
				break;
			case 32:
				opr_chop_lo = VexOperationType.Iop_32to16;
				opr_chop_hi = VexOperationType.Iop_32HIto16;
				break;
			case 64:
				opr_chop_lo = VexOperationType.Iop_64to32;
				opr_chop_hi = VexOperationType.Iop_64HIto32;
				break;
			case 128:
				opr_chop_lo = VexOperationType.Iop_128to64;
				opr_chop_hi = VexOperationType.Iop_128HIto64;
				break;
			default:
				break;
			}

			ComputationNode old_mem_lo = old_mem.cal(opr_chop_lo, graph);
			ComputationNode old_mem_hi = old_mem.cal(opr_chop_hi, graph);
			graph.assignValue(old_mem_lo, tmpLoNode);
			graph.assignValue(old_mem_hi, tmpHiNode);

			ComputationNode cond1 = old_mem_lo
					.cal(VexOperationType.valueOf("Iop_CmpEQ" + old_mem_lo.valType.outputType.numOfBit()), graph,
							expdLoNode)
					.cal(VexOperationType.Iop_1Uto32, graph);
			ComputationNode cond2 = old_mem_hi
					.cal(VexOperationType.valueOf("Iop_CmpEQ" + old_mem_hi.valType.outputType.numOfBit()), graph,
							expdHiNode)
					.cal(VexOperationType.Iop_1Uto32, graph);
			ComputationNode cond = cond1.cal(VexOperationType.valueOf("Iop_And" + cond1.valType.outputType.numOfBit()),
					graph, cond2);

			ComputationNode new_mem_lo = graph.createCondition(cond, dataLowNode, old_mem_lo);
			ComputationNode new_mem_hi = graph.createCondition(cond, dataHiNode, old_mem_hi);
			ComputationNode new_mem = new_mem_hi
					.cal(VexOperationType.valueOf("Iop_" + (readSize / 2) + "HLto" + readSize), graph, new_mem_lo);

			return graph.memory.writeMem(addrNode, new_mem, endness, graph);

		} else {

			ComputationNode expdLoNode = expdLo.getNode(graph, ina);
			ComputationNode dataLowNode = dataLow.getNode(graph, ina);
			ComputationNode tmpLoNode = graph.getTmpVar(oldLo_unsigned);
			ComputationNode addrNode = addr.getNode(graph, ina);

			ComputationNode old_mem_lo = graph.memory.readMem(ina, addrNode, dataLowNode.valType.outputType, endness,
					graph);
			graph.assignValue(old_mem_lo, tmpLoNode);

			ComputationNode cond = old_mem_lo.cal(
					VexOperationType.valueOf("Iop_CmpEQ" + old_mem_lo.valType.outputType.numOfBit()), graph,
					expdLoNode);
			ComputationNode new_mem_low = graph.createCondition(cond, dataLowNode, old_mem_lo);

			return graph.memory.writeMem(addrNode, new_mem_low, endness, graph);
		}
	}

	@Override
	public String toStr(VexToStrState state) {
		return "StmCAS (not implemented toStr())";
	}
}
