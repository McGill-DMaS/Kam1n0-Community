package ca.mcgill.sis.dmas.kam1n0.app.clone.asm;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;

@AppType(AsmApplicationMeta.appType)
public class AsmApplicationConfiguration extends ApplicationConfiguration {
	private static final long serialVersionUID = -2906612746988442788L;

	public NormalizationSetting normalizationSetting = new NormalizationSetting();
	public ArchitectureType architectureType = ArchitectureType.metapc;
	public int kStart = 18;
	public int kMax = 1024;
	public int mSplit = 20;
	public int l = 1;

	@Override
	public String createView() {
		return "apps/clone" + AsmApplicationMeta.appType + "/confg";
	}

	@Override
	public String createFragEdit() {
		return "apps/clone" + AsmApplicationMeta.appType + "/confg";
	}

	public NormalizationSetting getNormalizationSetting() {
		return normalizationSetting;
	}

	public void setNormalizationSetting(NormalizationSetting normalizationSetting) {
		this.normalizationSetting = normalizationSetting;
	}

	public ArchitectureType getArchitectureType() {
		return architectureType;
	}

	public void setArchitectureType(ArchitectureType architectureType) {
		this.architectureType = architectureType;
	}

	public int getkStart() {
		return kStart;
	}

	public void setkStart(int kStart) {
		this.kStart = kStart;
	}

	public int getkMax() {
		return kMax;
	}

	public void setkMax(int kMax) {
		this.kMax = kMax;
	}

	public int getmSplit() {
		return mSplit;
	}

	public void setmSplit(int mSplit) {
		this.mSplit = mSplit;
	}

	public int getL() {
		return l;
	}

	public void setL(int l) {
		this.l = l;
	}
}
