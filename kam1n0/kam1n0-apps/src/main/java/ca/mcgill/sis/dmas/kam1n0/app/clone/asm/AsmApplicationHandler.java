package ca.mcgill.sis.dmas.kam1n0.app.clone.asm;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import ca.mcgill.sis.dmas.kam1n0.AppPlatform.AppType;
import ca.mcgill.sis.dmas.kam1n0.app.clone.AbastractCloneSearchHandler;

@Controller
@RequestMapping(AsmApplicationMeta.appType)
@AppType(AsmApplicationMeta.appType)
public class AsmApplicationHandler extends AbastractCloneSearchHandler {

	public final static String VIEW_CLONE_FUNC = "apps/clone/asm-clone/app_func_clone_render";

	@Autowired
	public AsmApplicationHandler(AsmApplicationMeta meta) {
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

}
