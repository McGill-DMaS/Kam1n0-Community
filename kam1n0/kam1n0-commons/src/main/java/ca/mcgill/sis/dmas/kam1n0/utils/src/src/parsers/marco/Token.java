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

/**
 * A Preprocessor token.
 *
 * @see Preprocessor
 */
public final class Token {

    // public static final int	EOF        = -1;
    private final int type;
    private int line;
    private int column;
    private final Object value;
    private final String text;

    public Token(int type, int line, int column,
            String text, Object value) {
        this.type = type;
        this.line = line;
        this.column = column;
        this.text = text;
        this.value = value;
    }

    public Token(int type, int line, int column, String text) {
        this(type, line, column, text, null);
    }

    /* pp */ Token(int type, String text, Object value) {
        this(type, -1, -1, text, value);
    }

    /* pp */ Token(int type, String text) {
        this(type, text, null);
    }

    /* pp */ Token(int type) {
        this(type, TokenType.getTokenText(type));
    }

    /**
     * Returns the semantic type of this token.
     */
    public int getType() {
        return type;
    }

    /* pp */ void setLocation(int line, int column) {
        this.line = line;
        this.column = column;
    }

    /**
     * Returns the line at which this token started.
     *
     * Lines are numbered from zero.
     */
    public int getLine() {
        return line;
    }

    /**
     * Returns the column at which this token started.
     *
     * Columns are numbered from zero.
     */
    public int getColumn() {
        return column;
    }

    /**
     * Returns the original or generated text of this token.
     *
     * This is distinct from the semantic value of the token.
     *
     * @see #getValue()
     */
    public String getText() {
        return text;
    }

    /**
     * Returns the semantic value of this token.
     *
     * For strings, this is the parsed String.
     * For integers, this is an Integer object.
     * For other token types, as appropriate.
     *
     * @see #getText()
     */
    public Object getValue() {
        return value;
    }

    /**
     * Returns a description of this token, for debugging purposes.
     */
    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();

        buf.append('[').append(getTokenName(type));
        if (line != -1) {
            buf.append('@').append(line);
            if (column != -1)
                buf.append(',').append(column);
        }
        buf.append("]:");
        if (text != null)
            buf.append('"').append(text).append('"');
        else if (type > 3 && type < 256)
            buf.append((char) type);
        else
            buf.append('<').append(type).append('>');
        if (value != null)
            buf.append('=').append(value);
        return buf.toString();
    }

    /**
     * Returns the descriptive name of the given token type.
     *
     * This is mostly used for stringification and debugging.
     */
    public static String getTokenName(int type) {
        return TokenType.getTokenName(type);
    }

    public static final int AND_EQ = 257;
    public static final int ARROW = 258;
    public static final int CHARACTER = 259;
    public static final int CCOMMENT = 260;
    public static final int CPPCOMMENT = 261;
    public static final int DEC = 262;
    public static final int DIV_EQ = 263;
    public static final int ELLIPSIS = 264;
    public static final int EOF = 265;
    public static final int EQ = 266;
    public static final int GE = 267;
    public static final int HASH = 268;
    public static final int HEADER = 269;
    public static final int IDENTIFIER = 270;
    public static final int INC = 271;
    public static final int NUMBER = 272;
    public static final int LAND = 273;
    public static final int LAND_EQ = 274;
    public static final int LE = 275;
    public static final int LITERAL = 276;
    public static final int LOR = 277;
    public static final int LOR_EQ = 278;
    public static final int LSH = 279;
    public static final int LSH_EQ = 280;
    public static final int MOD_EQ = 281;
    public static final int MULT_EQ = 282;
    public static final int NE = 283;
    public static final int NL = 284;
    public static final int OR_EQ = 285;
    public static final int PASTE = 286;
    public static final int PLUS_EQ = 287;
    public static final int RANGE = 288;
    public static final int RSH = 289;
    public static final int RSH_EQ = 290;
    public static final int SQSTRING = 291;
    public static final int STRING = 292;
    public static final int SUB_EQ = 293;
    public static final int WHITESPACE = 294;
    public static final int XOR_EQ = 295;
    public static final int M_ARG = 296;
    public static final int M_PASTE = 297;
    public static final int M_STRING = 298;
    public static final int P_LINE = 299;
    public static final int INVALID = 300;

    /** The position-less space token. */
    /* pp */ static final Token space = new Token(WHITESPACE, -1, -1, " ");
}
