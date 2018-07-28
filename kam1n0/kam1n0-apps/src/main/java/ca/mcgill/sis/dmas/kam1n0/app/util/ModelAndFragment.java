package ca.mcgill.sis.dmas.kam1n0.app.util;

public class ModelAndFragment {
	public ModelAndFragment(String fragment, Object model) {
		this.fragment = fragment;
		this.model = model;
	}

	public ModelAndFragment() {
	}

	public Object model;
	public String fragment;
}