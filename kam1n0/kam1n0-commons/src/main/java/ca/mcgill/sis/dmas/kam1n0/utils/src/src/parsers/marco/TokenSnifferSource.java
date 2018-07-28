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

import java.io.IOException;
import java.util.List;

import static ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco.Token.EOF;

@Deprecated
/* pp */ class TokenSnifferSource extends Source {

    private final List<Token> target;

    /* pp */ TokenSnifferSource(List<Token> target) {
        this.target = target;
    }

    public Token token()
            throws IOException,
            LexerException {
        Token tok = getParent().token();
        if (tok.getType() != EOF)
            target.add(tok);
        return tok;
    }

    @Override
    public String toString() {
        return getParent().toString();
    }
}
