package ca.mcgill.sis.dmas.kam1n0.app;

import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class ApplicationInfoValidator implements Validator {

	@Override
	public boolean supports(Class<?> clazz) {
		return ApplicationInfo.class.equals(clazz);
	}

	@Override
	public void validate(Object target, Errors errors) {
		ApplicationInfo app = (ApplicationInfo) target;

		ValidationUtils.rejectIfEmptyOrWhitespace(errors, "name", "NotEmpty");
		if (app.name.length() < 3 || app.name.length() > 64) {
			errors.rejectValue("name", "Length");
		}
		if (!app.name.matches("\\S+")) {
			errors.rejectValue("name", "Space");
		}

		ValidationUtils.rejectIfEmptyOrWhitespace(errors, "applicationType", "NotEmpty");

		ValidationUtils.rejectIfEmptyOrWhitespace(errors, "title", "NotEmpty");
		if (app.getTitle().length() < 3 || app.getTitle().length() > 64) {
			errors.rejectValue("title", "Length");
		}
		ValidationUtils.rejectIfEmpty(errors, "configuration", "NotEmpty");
	}

}
