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
package ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam;

import java.util.List;

import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.AsmProcessor;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting.NormalizationLevel;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.AsmObjectFactory;
import ca.mcgill.sis.dmas.kam1n0.graph.LogicGraph;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.indexer.BlockIndexerLshKLAdaptive;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.DifferentialIndexCassandra;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.DifferentialIndexRam;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.DifferentialSymbolicIndexer;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.LogicGraphFactory;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureConstructor;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FeatureMneOprAllFreq;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.Features;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.features.FreqFeatures;
import ca.mcgill.sis.dmas.kam1n0.utils.datastore.CassandraInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.executor.SparkInstance;
import ca.mcgill.sis.dmas.kam1n0.utils.hash.HashSchema.HashSchemaTypes;

public class DetectorsKam {

	/**
	 * RAM version
	 * 
	 * @param spark
	 * @param cassandra
	 * @param platformName
	 * @param appName
	 * @param type
	 * @return
	 */
	public static FunctionCloneDetector getLshAdaptiveSubGraphFunctionCloneDetectorRam(SparkInstance spark,
			String platformName, String appName, ArchitectureType type) {
		NormalizationSetting setting = NormalizationSetting.New();
		setting.setNormalizationLevel(NormalizationLevel.NORM_LENGTH);
		AsmObjectFactory factory = AsmObjectFactory.init(spark, platformName, appName);
		AsmProcessor processor = new AsmProcessor(type.retrieveDefinition(), setting);
		FunctionSubgraphDetector detector = new FunctionSubgraphDetector(//
				factory, //
				spark, //
				new BlockIndexerLshKLAdaptive(//
						spark, //
						null, //
						factory, //
						new FeatureConstructor(processor.normalizer, FreqFeatures.getFeatureMemOprFreq(),
								FreqFeatures.getFeatureMemGramFreq(2)), //
						16, // start K
						1024, // max K
						1, // l
						30, // m
						HashSchemaTypes.SimHash, true), //
				1, // min block length
				false);// best 256-1024-1-30-4
		// detector.fixTopK = 10;
		return detector;
	}

	/**
	 * Cassandra version
	 * 
	 * @param sparkInstance
	 * @param cassandraInstance
	 * @param factory
	 * @param processor
	 * @param startK
	 * @param K
	 * @param L
	 * @param m
	 * @param minBlckLength
	 * @return
	 */
	public static FunctionCloneDetector getLshAdaptiveSubGraphFunctionCloneDetectorCassandra(
			SparkInstance sparkInstance, CassandraInstance cassandraInstance, AsmObjectFactory factory,
			AsmProcessor processor, int startK, int K, int L, int m, int minBlckLength) {
		return new FunctionSubgraphDetector(//
				factory, //
				sparkInstance, //
				new BlockIndexerLshKLAdaptive(//
						sparkInstance, //
						cassandraInstance, //
						factory, //
						new FeatureConstructor(processor.normalizer, new FeatureMneOprAllFreq()), // \
						startK, //
						K, //
						L, //
						m, HashSchemaTypes.SimHash, false), //
				minBlckLength, //
				false);//
	}

	/**
	 * Cassandra version
	 * 
	 * @param sparkInstance
	 * @param cassandraInstance
	 * @param factory
	 * @param inMem
	 * @param processor
	 * @param startK
	 * @param K
	 * @param L
	 * @param m
	 * @param minBlckLength
	 * @param features
	 * @return
	 */
	public static FunctionCloneDetector getLshAdaptiveSubGraphFunctionCloneDetectorCassandra(
			SparkInstance sparkInstance, CassandraInstance cassandraInstance, AsmObjectFactory factory,
			AsmProcessor processor, int startK, int K, int L, int m, int minBlckLength, List<Features> features) {
		return new FunctionSubgraphDetector(//
				factory, //
				sparkInstance, //
				new BlockIndexerLshKLAdaptive(//
						sparkInstance, //
						cassandraInstance, //
						factory, //
						new FeatureConstructor(processor.normalizer, features), // \
						startK, //
						K, //
						L, //
						m, HashSchemaTypes.SimHash, //
						false), // inMem?
				minBlckLength, //
				false);//
	}

	// symoblic version:

	public static FunctionCloneDetector getSymbolicSubGraphFunctionCloneDetectorRam(SparkInstance spark,
			String platformName, String appName, int maxSize, int maxDepth, int bound, int debuglevel) {
		AsmObjectFactory factory = AsmObjectFactory.init(spark, platformName, appName);
		LogicGraphFactory logicFactory = LogicGraphFactory.init(spark, platformName, appName);
		DifferentialSymbolicIndexer index = new DifferentialSymbolicIndexer(//
				spark, //
				factory, //
				logicFactory, //
				0, // seed
				maxSize, //
				maxDepth, //
				bound, debuglevel, new DifferentialIndexRam());
		return index.new Detector(factory);
	}

	public static FunctionCloneDetector getSymbolicSubGraphFunctionCloneDetectorCassandra(AsmObjectFactory factory,
			LogicGraphFactory logicFactory, SparkInstance spark, CassandraInstance cassandra, int maxSize, int maxDepth,
			int bound, int debuglevel) {
		DifferentialSymbolicIndexer index = new DifferentialSymbolicIndexer(//
				spark, //
				factory, //
				logicFactory, //
				0, // seed
				maxSize, //
				maxDepth, //
				bound, 2, //
				new DifferentialIndexCassandra(//
						spark, //
						cassandra, //
						"symbolic"));
		return index.new Detector(factory);
	}

}
