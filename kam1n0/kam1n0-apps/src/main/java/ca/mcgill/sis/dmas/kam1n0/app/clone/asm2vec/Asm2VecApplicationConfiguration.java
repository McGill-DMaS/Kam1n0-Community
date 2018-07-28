package ca.mcgill.sis.dmas.kam1n0.app.clone.asm2vec;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.ApplicationConfiguration;
import ca.mcgill.sis.dmas.kam1n0.commons.defs.Architecture.ArchitectureType;
import ca.mcgill.sis.dmas.kam1n0.framework.disassembly.NormalizationSetting;
import ca.mcgill.sis.dmas.nlp.model.astyle._1_original.LearnerAsm2VecNew.Asm2VecNewParam;

@AppType(Asm2VecApplicationMeta.appType)
public class Asm2VecApplicationConfiguration extends ApplicationConfiguration {
	public int getIteration() {
		return iteration;
	}

	public void setIteration(int iteration) {
		this.iteration = iteration;
	}

	public int getNegative_samples() {
		return negative_samples;
	}

	public void setNegative_samples(int negative_samples) {
		this.negative_samples = negative_samples;
	}

	public int getMin_frequeceny() {
		return min_frequeceny;
	}

	public void setMin_frequeceny(int min_frequeceny) {
		this.min_frequeceny = min_frequeceny;
	}

	public int getWlk() {
		return wlk;
	}

	public void setWlk(int wlk) {
		this.wlk = wlk;
	}

	public int getDim() {
		return dim;
	}

	public void setDim(int dim) {
		this.dim = dim;
	}

	private static final long serialVersionUID = -2906612746988442788L;

	public ArchitectureType architectureType = ArchitectureType.metapc;
	public int kStart = 4;
	public int kMax = 128;
	public int mSplit = 100;
	public int l = 15;

	public int iteration = 20;
	public int negative_samples = 25;
	public int min_frequeceny = 1;
	public int dim = 100;
	public int wlk = 1;

	public Asm2VecNewParam convertToParam() {
		Asm2VecNewParam param = new Asm2VecNewParam();
		param.optm_iteration = iteration;
		param.optm_negSample = negative_samples;
		param.min_freq = min_frequeceny;
		param.vec_dim = dim;
		param.num_rand_wlk = wlk;
		return param;
	}

	@Override
	public String createView() {
		return "apps/clone" + Asm2VecApplicationMeta.appType + "/confg";
	}

	@Override
	public String createFragEdit() {
		return "apps/clone" + Asm2VecApplicationMeta.appType + "/confg";
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
