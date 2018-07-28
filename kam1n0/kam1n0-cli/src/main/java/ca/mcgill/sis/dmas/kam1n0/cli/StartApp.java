package ca.mcgill.sis.dmas.kam1n0.cli;

import ca.mcgill.sis.dmas.env.ArgumentParser;
import ca.mcgill.sis.dmas.kam1n0.Application;

public class StartApp extends CLIFunction {

	private ArgumentParser parser = ArgumentParser.create(StartApp.class.getSimpleName());

	@Override
	public ArgumentParser getParser() {
		return parser;
	}

	@Override
	public String getDescription() {
		return "Start the application service.";
	}

	@Override
	public String getCode() {
		return "start";
	}

	@Override
	public void process(String[] args) throws Exception {
		Application.main(args);

	}

	@Override
	public String getCategory() {
		return "Service";
	}

}
