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
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import javax.annotation.Nonnull;

/**
 * A {@link Source} which lexes a file.
 *
 * The input is buffered.
 *
 * @see Source
 */
public class FileLexerSource extends LexerSource {

    private final String path;
    private final File file;

    /**
     * Creates a new Source for lexing the given File.
     *
     * Preprocessor directives are honoured within the file.
     */
    public FileLexerSource(@Nonnull File file, String path)
            throws IOException {
        super(
                new BufferedReader(
                        new FileReader(
                                file
                        )
                ),
                true
        );

        this.file = file;
        this.path = path;
    }

    public FileLexerSource(@Nonnull File file)
            throws IOException {
        this(file, file.getPath());
    }

    public FileLexerSource(@Nonnull String path)
            throws IOException {
        this(new File(path), path);
    }

    @Nonnull
    public File getFile() {
        return file;
    }

    /**
     * This is not necessarily the same as getFile().getPath() in case we are in a chroot.
     */
    @Override
    public String getPath() {
        return path;
    }

    @Override
    public String getName() {
        return getPath();
    }

    @Override
    public String toString() {
        return "file " + getPath();
    }
}
