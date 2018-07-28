package ca.mcgill.sis.dmas.kam1n0.app.clone.asm2vec;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.clone.AbastractCloneSearchHandler;

@Controller
@RequestMapping(Asm2VecApplicationMeta.appType)
@AppType(Asm2VecApplicationMeta.appType)
public class Asm2VecApplicationHandler extends AbastractCloneSearchHandler {

	public final static String VIEW_CLONE_FUNC = "apps/clone/asm2vec-clone/app_func_clone_render";
	public final static String VIEW_BIN_INDEX = "apps/clone/asm2vec-clone/app_request_bin_index";

	@Autowired
	public Asm2VecApplicationHandler(Asm2VecApplicationMeta meta) {
		super(meta);
	}

	@Override
	public List<String> getExamples() {
		return Arrays.asList("adler32.txt");
	}

	@Override
	public String getFuncCloneRenderFragment() {
		return VIEW_CLONE_FUNC;
	}

	@Override
	public String getBinIndexFragment() {
		return VIEW_BIN_INDEX;
	}

	@RequestMapping(value = "/{appId:.+}/reindex", method = RequestMethod.POST)
	public final @ResponseBody Map<String, Object> reIndex() {
		return null;
	}

}
