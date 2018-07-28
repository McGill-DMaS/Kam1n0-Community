package ca.mcgill.sis.dmas.kam1n0.app.adata;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class BlockDataUnit implements Serializable {
	private static final long serialVersionUID = 8542513933109523168L;
	public String name;
	public String blockID;
	public String functionId;
	public String sea;
	public List<String> srcCodes;

	@JsonIgnore
	public Map<String, Object> appAttr = new HashMap<>();

	@JsonAnyGetter
	public Map<String, Object> getProperties() {
		return appAttr;
	}

	public BlockDataUnit() {
	}
}