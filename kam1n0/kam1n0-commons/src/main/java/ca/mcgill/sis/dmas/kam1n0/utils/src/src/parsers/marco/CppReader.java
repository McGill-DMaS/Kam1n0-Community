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

import java.io.Closeable;
import java.io.IOException;
import java.io.Reader;

import javax.annotation.Nonnull;

import static ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco.Token.CCOMMENT;
import static ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco.Token.CPPCOMMENT;
import static ca.mcgill.sis.dmas.kam1n0.utils.src.src.parsers.marco.Token.EOF;

/**
 * A Reader wrapper around the Preprocessor.
 *
 * This is a utility class to provide a transparent {@link Reader}
 * which preprocesses the input text.
 *
 * @see Preprocessor
 * @see Reader
 */
public class CppReader extends Reader implements Closeable {

    private final Preprocessor cpp;
    private String token;
    private int idx;

    public CppReader(@Nonnull final Reader r) {
        cpp = new Preprocessor(new LexerSource(r, true) {
            @Override
            public String getName() {
                return "<CppReader Input@"
                        + System.identityHashCode(r) + ">";
            }
        });
        token = "";
        idx = 0;
    }

    public CppReader(@Nonnull Preprocessor p) {
        cpp = p;
        token = "";
        idx = 0;
    }

    /**
     * Returns the Preprocessor used by this CppReader.
     */
    @Nonnull
    public Preprocessor getPreprocessor() {
        return cpp;
    }

    /**
     * Defines the given name as a macro.
     *
     * This is a convnience method.
     */
    public void addMacro(@Nonnull String name)
            throws LexerException {
        cpp.addMacro(name);
    }

    /**
     * Defines the given name as a macro.
     *
     * This is a convnience method.
     */
    public void addMacro(@Nonnull String name, @Nonnull String value)
            throws LexerException {
        cpp.addMacro(name, value);
    }

    private boolean refill()
            throws IOException {
        try {
            assert cpp != null : "cpp is null : was it closed?";
            if (token == null)
                return false;
            while (idx >= token.length()) {
                Token tok = cpp.token();
                switch (tok.getType()) {
                    case EOF:
                        token = null;
                        return false;
                    case CCOMMENT:
                    case CPPCOMMENT:
                        if (!cpp.getFeature(Feature.KEEPCOMMENTS)) {
                            token = " ";
                            break;
                        }
                    default:
                        token = tok.getText();
                        break;
                }
                idx = 0;
            }
            return true;
        } catch (LexerException e) {
            throw new IOException(String.valueOf(e), e);
        }
    }

    @Override
    public int read()
            throws IOException {
        if (!refill())
            return -1;
        return token.charAt(idx++);
    }

    /* XXX Very slow and inefficient. */
    public int read(char cbuf[], int off, int len)
            throws IOException {
        if (token == null)
            return -1;
        for (int i = 0; i < len; i++) {
            int ch = read();
            if (ch == -1)
                return i;
            cbuf[off + i] = (char) ch;
        }
        return len;
    }

    @Override
    public void close()
            throws IOException {
        cpp.close();
        token = null;
    }

}
