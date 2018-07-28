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

import java.io.File;
import java.io.IOException;

/**
 * A virtual filesystem implementation using java.io in a virtual
 * chroot.
 */
public class ChrootFileSystem implements VirtualFileSystem {

    private File root;

    public ChrootFileSystem(File root) {
        this.root = root;
    }

    @Override
    public VirtualFile getFile(String path) {
        return new ChrootFile(path);
    }

    @Override
    public VirtualFile getFile(String dir, String name) {
        return new ChrootFile(dir, name);
    }

    private class ChrootFile extends File implements VirtualFile {

        private File rfile;

        public ChrootFile(String path) {
            super(path);
        }

        public ChrootFile(String dir, String name) {
            super(dir, name);
        }

        /* private */
        public ChrootFile(File dir, String name) {
            super(dir, name);
        }

        @Override
        public ChrootFile getParentFile() {
            return new ChrootFile(getParent());
        }

        @Override
        public ChrootFile getChildFile(String name) {
            return new ChrootFile(this, name);
        }

        @Override
        public boolean isFile() {
            File real = new File(root, getPath());
            return real.isFile();
        }

        @Override
        public Source getSource() throws IOException {
            return new FileLexerSource(new File(root, getPath()),
                    getPath());
        }
    }

}
