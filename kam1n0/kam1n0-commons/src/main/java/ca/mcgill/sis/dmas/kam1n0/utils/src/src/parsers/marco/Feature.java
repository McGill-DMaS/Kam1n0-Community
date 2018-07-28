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
 * Features of the Preprocessor, which may be enabled or disabled.
 */
public enum Feature {

    /** Supports ANSI digraphs. */
    DIGRAPHS,
    /** Supports ANSI trigraphs. */
    TRIGRAPHS,
    /** Outputs linemarker tokens. */
    LINEMARKERS,
    /** Reports tokens of type INVALID as errors. */
    CSYNTAX,
    /** Preserves comments in the lexed output. */
    KEEPCOMMENTS,
    /** Preserves comments in the lexed output, even when inactive. */
    KEEPALLCOMMENTS,
    DEBUG,
    /** Supports lexing of objective-C. */
    OBJCSYNTAX,
    INCLUDENEXT,
    /** Random extensions. */
    PRAGMA_ONCE
}
