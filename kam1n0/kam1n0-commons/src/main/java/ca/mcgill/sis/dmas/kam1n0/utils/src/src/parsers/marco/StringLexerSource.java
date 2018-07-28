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
package ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco;

import java.io.StringReader;

/**
 * A Source for lexing a String.
 *
 * This class is used by token pasting, but can be used by user
 * code.
 */
public class StringLexerSource extends LexerSource {

    /**
     * Creates a new Source for lexing the given String.
     *
     * @param ppvalid true if preprocessor directives are to be
     *	honoured within the string.
     */
    public StringLexerSource(String string, boolean ppvalid) {
        super(new StringReader(string), ppvalid);
    }

    /**
     * Creates a new Source for lexing the given String.
     *
     * By default, preprocessor directives are not honoured within
     * the string.
     */
    public StringLexerSource(String string) {
        this(string, false);
    }

    @Override
    public String toString() {
        return "string literal";
    }
}
