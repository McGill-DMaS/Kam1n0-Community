package ca.mcgill.sis.dmas.kam1n0.app.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class UserInfoValidator implements Validator {

	@Autowired
	private UserFactory factory;

	@Override
	public boolean supports(Class<?> aClass) {
		return UserInfo.class.equals(aClass);
	}

	@Override
	public void validate(Object o, Errors errors) {
		UserInfo user = (UserInfo) o;

		if (!user.aggreeTLicense)
			errors.rejectValue("aggreeTLicense", "Agree");

		ValidationUtils.rejectIfEmptyOrWhitespace(errors, "userName", "NotEmpty");
		if (user.getUserName().length() < 3 || user.getUserName().length() > 48) {
			errors.rejectValue("userName", "Length");
		}
		if (user.getUserName().equalsIgnoreCase(UserFactory.SYS_USER_NAME_IDA)) {
			errors.rejectValue("userName", "NameExisted");
		}

		if (!user.getUserName().matches("\\S+")) {
			errors.rejectValue("userName", "Space");
		}
		if (factory.findUser(user.getUserName()) != null) {
			errors.rejectValue("userName", "NameExisted");
		}

		ValidationUtils.rejectIfEmptyOrWhitespace(errors, "email", "NotEmpty");
		if (user.getEmail().length() < 3 || user.getEmail().length() > 48) {
			errors.rejectValue("email", "Length");
		}

		ValidationUtils.rejectIfEmptyOrWhitespace(errors, "credential", "NotEmpty");
		if (user.getCredential().length() < 3 || user.getCredential().length() > 48) {
			errors.rejectValue("credential", "Length");
		}

	}
}
