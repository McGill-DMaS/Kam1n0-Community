package ca.mcgill.sis.dmas.kam1n0.app;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class ApplicationConfiguration implements Serializable {
	private static final long serialVersionUID = 1175155024992859989L;

	@Override
	public String toString() {
		try {
			return (new ObjectMapper()).disable(SerializationFeature.FAIL_ON_EMPTY_BEANS).writeValueAsString(this);
		} catch (Exception e) {
			return super.toString();
		}
	}

	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return obj instanceof ApplicationConfiguration && this.toString().equals(obj.toString());
	}

	public String createFragEdit() {
		return null;
	}

	public String createView() {
		return null;
	}

	public String appType() {
		AppType ann = this.getClass().getAnnotation(AppType.class);
		return ann.value();
	}
}
