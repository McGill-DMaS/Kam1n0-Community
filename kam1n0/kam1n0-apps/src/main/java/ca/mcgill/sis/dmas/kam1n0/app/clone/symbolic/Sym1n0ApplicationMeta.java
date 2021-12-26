package ca.mcgill.sis.dmas.kam1n0.app.clone.symbolic;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationInfo;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationMeta;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationResources;
import ca.mcgill.sis.dmas.kam1n0.app.adata.FunctionDataUnit;
import ca.mcgill.sis.dmas.kam1n0.AppController;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform;
import ca.mcgill.sis.dmas.kam1n0.GlobalResources;
import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.clone.CloneSearchResources;
import ca.mcgill.sis.dmas.kam1n0.framework.storage.Function;
import ca.mcgill.sis.dmas.kam1n0.graph.BlockLogicWrapper;
import ca.mcgill.sis.dmas.kam1n0.graph.Kam1n0SymbolicModule;
import ca.mcgill.sis.dmas.kam1n0.graph.LogicGraph;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.FunctionCloneDetector;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.DetectorsKam;
import ca.mcgill.sis.dmas.kam1n0.problem.clone.detector.kam.symbolic.LogicGraphFactory;
import ca.mcgill.sis.dmas.kam1n0.vex.BinaryRawFuncParser;

@Component
@AppType(Sym1n0ApplicationMeta.appType)
public class Sym1n0ApplicationMeta extends ApplicationMeta {

	public final static String appType = "/sym1n0-clone";

	@Override
	public String getAppType() {
		return appType;
	}

	private static Logger logger = LoggerFactory.getLogger(Sym1n0ApplicationMeta.class);

	private LogicGraphFactory logicFactory;

	private BinaryRawFuncParser parser = new BinaryRawFuncParser();

	Cache<Sym1n0ApplicationConfiguration, CloneSearchResources> map = CacheBuilder.newBuilder().maximumSize(5).build();

	@Autowired
	public Sym1n0ApplicationMeta(GlobalResources res, AppPlatform platform, AppController controller) {
		super(platform, controller);

		logicFactory = LogicGraphFactory.init(res.spark, res.cassandra, res.platform_name, "sym1n0");
		Kam1n0SymbolicModule.setup();
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T extends ApplicationResources> T getResource(long appId) {
		ApplicationInfo info = getInfo(appId);
		Sym1n0ApplicationConfiguration conf = (Sym1n0ApplicationConfiguration) info.configuration;
		CloneSearchResources val = map.getIfPresent(info.configuration);
		if (val == null) {
			try {
				logger.info("Loading new resources. It may take a while to process the first query.");
				FunctionCloneDetector detector = DetectorsKam.getSymbolicSubGraphFunctionCloneDetectorCassandra(
						platform.objectFactory, logicFactory, platform.spark, platform.cassandra, conf.maxSize,
						conf.maxDepth, conf.bound, 2);
				detector.init();
				val = new CloneSearchResources(platform.objectFactory, detector, parser);
				map.put(conf, val);
			} catch (Exception e) {
				logger.error("Failed to get resources.", e);
			}
		}
		return (T) val;
	}

	@Override
	public void cleanUpResource(long appId) {
		logicFactory.delete(appId);
		ApplicationInfo info = getInfo(appId);
		Sym1n0ApplicationConfiguration conf = (Sym1n0ApplicationConfiguration) info.configuration;
		CloneSearchResources res = getResource(appId);
		res.detector.clear(appId);
		map.invalidate(conf);
	}

	@Override
	/**
	 * Override the parent getFunction method to fill in needed attributes. All the
	 * added attributes will properly get propergated to all UI.
	 */
	public FunctionDataUnit getFunction(long appId, long fid) {
		Function func = this.platform.getFunction(appId, fid);

		if (func != null) {
			func = this.fillAll(appId, func);
			return new FunctionDataUnit(func, false, true);
		}
		return null;
	}

	public Function fillAll(long appId, Function func) {
		// parallel to avoid I/O conjestion.
		func.blocks = func.blocks.stream().parallel().map(node -> {
			LogicGraph logic = this.logicFactory.getLogicGraph(appId, node.blockId);
			List<List<String>> vex = this.logicFactory.getVex(appId, node.blockId);
			return new BlockLogicWrapper(node, vex, logic);
			// the code block below is reserved for sampling (show some I/O samples in the
			// graph)
			// if (box != null) {
			// block.getLogic().toConfigurable(box.ctx).getConfigurations(true).forEach(conf
			// -> {
			// conf.setValue(box.defaultValueForInputIfNotSuplied);
			// RunResult result = conf.run(box);
			// VisualNode vnode =
			// node.logic.varNameToNodeMap.get(conf.outputSymbol.cNode.varName);
			// vnode.content.add(" = 0x" + result.output.value);
			// if
			// (conf.configurable.outputSymbols.containsKey(conf.outputSymbol.cNode.varName))
			// node.logic.outputs.content
			// .add(conf.outputSymbol.cNode.varName + " = 0x" + result.output.value);
			// if (node.logic.inputs.content.size() < 2)
			// result.inputs.stream().map(input -> input.sym.cNode.varName + " = 0x" +
			// input.value)
			// .forEach(node.logic.inputs.content::add);
			// });
			// }
		}).collect(Collectors.toList());
		return func;
	}

}
