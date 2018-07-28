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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.annotation.Nonnull;

/**
 *
 * @author shevek
 */
public class ResourceFileSystem implements VirtualFileSystem {

    private final ClassLoader loader;

    public ResourceFileSystem(@Nonnull ClassLoader loader) {
        this.loader = loader;
    }

    @Override
    public VirtualFile getFile(String path) {
        return new ResourceFile(loader, path);
    }

    @Override
    public VirtualFile getFile(String dir, String name) {
        return getFile(dir + "/" + name);
    }

    private class ResourceFile implements VirtualFile {

        private final ClassLoader loader;
        private final String path;

        public ResourceFile(ClassLoader loader, String path) {
            this.loader = loader;
            this.path = path;
        }

        @Override
        public boolean isFile() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public String getPath() {
            return path;
        }

        @Override
        public String getName() {
            return path.substring(path.lastIndexOf('/') + 1);
        }

        @Override
        public ResourceFile getParentFile() {
            int idx = path.lastIndexOf('/');
            if (idx < 1)
                return null;
            return new ResourceFile(loader, path.substring(0, idx));
        }

        @Override
        public ResourceFile getChildFile(String name) {
            return new ResourceFile(loader, path + "/" + name);
        }

        @Override
        public Source getSource() throws IOException {
            InputStream stream = loader.getResourceAsStream(path);
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
            return new LexerSource(reader, true);
        }
    }
}
