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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.rendezvous;

import java.util.ArrayList;

import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;

public class DetectorsRendezvous {

	public static FunctionCloneDetector getDetectorCompositeRam() {
		return new DetectorComposite(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "rendezvous", "composite"));
	}

	public static FunctionCloneDetector getDetectorConstantRam(AsmProcessor processor) {
		return new DetectorConstant(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "rendezvous", "constant"),
				processor);
	}

	public static FunctionCloneDetector getDetectorGraphletRam() {
		return new DetectorGraphlet(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "rendezvous", "graphlet"));
	}

	public static FunctionCloneDetector getDetectorGraphletColoredRam() {
		return new DetectorGraphletColored(AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()),
				"rendezvous", "graphlet-colored"));
	}

	public static FunctionCloneDetector getDetectorGraphletExtendedRam() {
		return new DetectorGraphletExtended(AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()),
				"rendezvous", "graphlet-extended"));
	}

	public static FunctionCloneDetector getDetectorMixedGramRam() {
		return new DetectorMixedGram(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "rendezvous", "composite"));
	}

	public static FunctionCloneDetector getDetectorMixedGraphRam() {
		return new DetectorMixedGraph(AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()),
				"rendezvous", "mixed-graph"));
	}

	public static FunctionCloneDetector getDetectorNgramRam() {
		return new DetectorNgram(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "rendezvous", "ngram"));
	}

	public static FunctionCloneDetector getDetectorNpermRam() {
		return new DetectorNperm(
				AsmObjectFactory.init(SparkInstance.createLocalInstance(new ArrayList<>()), "rendezvous", "nperm"));
	}

}
