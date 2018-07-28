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

import javax.annotation.Nonnull;

/**
 * A handler for preprocessor events, primarily errors and warnings.
 *
 * If no PreprocessorListener is installed in a Preprocessor, all
 * error and warning events will throw an exception. Installing a
 * listener allows more intelligent handling of these events.
 */
public interface PreprocessorListener {

    /**
     * Handles a warning.
     *
     * The behaviour of this method is defined by the
     * implementation. It may simply record the error message, or
     * it may throw an exception.
     */
    public void handleWarning(@Nonnull Source source, int line, int column,
            @Nonnull String msg)
            throws LexerException;

    /**
     * Handles an error.
     *
     * The behaviour of this method is defined by the
     * implementation. It may simply record the error message, or
     * it may throw an exception.
     */
    public void handleError(@Nonnull Source source, int line, int column,
            @Nonnull String msg)
            throws LexerException;

    public enum SourceChangeEvent {

        SUSPEND, PUSH, POP, RESUME;
    }

    public void handleSourceChange(@Nonnull Source source, @Nonnull SourceChangeEvent event);

}
