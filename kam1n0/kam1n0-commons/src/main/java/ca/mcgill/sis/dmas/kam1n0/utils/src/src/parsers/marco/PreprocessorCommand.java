/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

/**
 *
 * @author shevek
 */
public enum PreprocessorCommand {

    PP_DEFINE("define"),
    PP_ELIF("elif"),
    PP_ELSE("else"),
    PP_ENDIF("endif"),
    PP_ERROR("error"),
    PP_IF("if"),
    PP_IFDEF("ifdef"),
    PP_IFNDEF("ifndef"),
    PP_INCLUDE("include"),
    PP_LINE("line"),
    PP_PRAGMA("pragma"),
    PP_UNDEF("undef"),
    PP_WARNING("warning"),
    PP_INCLUDE_NEXT("include_next"),
    PP_IMPORT("import");
    private final String text;
    /* pp */ PreprocessorCommand(String text) {
        this.text = text;
    }

    @CheckForNull
    public static PreprocessorCommand forText(@Nonnull String text) {
        for (PreprocessorCommand ppcmd : PreprocessorCommand.values())
            if (ppcmd.text.equals(text))
                return ppcmd;
        return null;
    }
}
