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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * A {@link Source} which lexes a file.
 *
 * The input is buffered.
 *
 * @see Source
 */
public class InputLexerSource extends LexerSource {

    /**
     * Creates a new Source for lexing the given Reader.
     *
     * Preprocessor directives are honoured within the file.
     */
    public InputLexerSource(InputStream input)
            throws IOException {
        super(
                new BufferedReader(
                        new InputStreamReader(
                                input
                        )
                ),
                true
        );
    }

    @Override
    public String getPath() {
        return "<standard-input>";
    }

    @Override
    public String getName() {
        return "standard input";
    }

    @Override
    public String toString() {
        return String.valueOf(getPath());
    }
}
