package ca.mcgill.sis.dmas.kam1n0.app.clone.symbolic;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;

@AppType(Sym1n0ApplicationMeta.appType)
public class Sym1n0ApplicationConfiguration extends ApplicationConfiguration {
	private static final long serialVersionUID = -2906612746988442788L;

	public int maxSize = 40;
	public int maxDepth = 30;
	public int bound = 3000;

	public int getMaxSize() {
		return maxSize;
	}

	public void setMaxSize(int maxSize) {
		this.maxSize = maxSize;
	}

	public int getMaxDepth() {
		return maxDepth;
	}

	public void setMaxDepth(int maxDepth) {
		this.maxDepth = maxDepth;
	}

	public int getBound() {
		return bound;
	}

	public void setBound(int bound) {
		this.bound = bound;
	}

	@Override
	public String createView() {
		return "apps/clone" + Sym1n0ApplicationMeta.appType + "/confg";
	}

	@Override
	public String createFragEdit() {
		return "apps/clone" + Sym1n0ApplicationMeta.appType + "/confg";
	}

}
