package kam1n0;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * A helper to copy resources from a JAR file into a directory.
 * from
 * https://stackoverflow.com/a/58318009
 */
public final class ResourceCopy {

    /**
     * URI prefix for JAR files.
     */
    private static final String JAR_URI_PREFIX = "jar:file:";

    /**
     * The default buffer size.
     */
    private static final int BUFFER_SIZE = 8 * 1024;

    /**
     * Copies a set of resources into a temporal directory, optionally preserving
     * the paths of the resources.
     * @param preserve Whether the files should be placed directly in the
     *  directory or the source path should be kept
     * @param paths The paths to the resources
     * @return The temporal directory
     * @throws IOException If there is an I/O error
     */
    public File copyResourcesToTempDir(final boolean preserve,
        final String... paths)
        throws IOException {
        final File parent = new File(System.getProperty("java.io.tmpdir"));
        File directory;
        do {
            directory = new File(parent, String.valueOf(System.nanoTime()));
        } while (!directory.mkdir());
        return this.copyResourcesToDir(directory, preserve, paths);
    }

    /**
     * Copies a set of resources into a directory, preserving the paths
     * and names of the resources.
     * @param directory The target directory
     * @param preserve Whether the files should be placed directly in the
     *  directory or the source path should be kept
     * @param paths The paths to the resources
     * @return The temporal directory
     * @throws IOException If there is an I/O error
     */
    public File copyResourcesToDir(final File directory, final boolean preserve,
        final String... paths) throws IOException {
        for (final String path : paths) {
            final File target;
            if (preserve) {
                target = new File(directory, path);
                target.getParentFile().mkdirs();
            } else {
                target = new File(directory, new File(path).getName());
            }
            this.writeToFile(
                Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream(path),
                target
            );
        }
        return directory;
    }

    /**
     * Copies a resource directory from inside a JAR file to a target directory.
     * @param source The JAR file
     * @param path The path to the directory inside the JAR file
     * @param target The target directory
     * @throws IOException If there is an I/O error
     */
    public void copyResourceDirectory(final JarFile source, final String path,
        final File target) throws IOException {
        final Enumeration<JarEntry> entries = source.entries();
        final String newpath = String.format("%s/", path);
        while (entries.hasMoreElements()) {
            final JarEntry entry = entries.nextElement();
            if (entry.getName().startsWith(newpath) && !entry.isDirectory()) {
                final File dest =
                    new File(target, entry.getName().substring(newpath.length()));
                final File parent = dest.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                this.writeToFile(source.getInputStream(entry), dest);
            }
        }
    }

    /**
     * The JAR file containing the given class.
     * @param clazz The class
     * @return The JAR file or null
     * @throws IOException If there is an I/O error
     */
    public Optional<JarFile> jar(final Class<?> clazz) throws IOException {
        final String path =
            String.format("/%s.class", clazz.getName().replace('.', '/'));
        final URL url = clazz.getResource(path);
        Optional<JarFile> optional = Optional.empty();
        if (url != null) {
            final String jar = url.toString();
            final int bang = jar.indexOf('!');
            if (jar.startsWith(ResourceCopy.JAR_URI_PREFIX) && bang != -1) {
                optional = Optional.of(
                    new JarFile(
                        jar.substring(ResourceCopy.JAR_URI_PREFIX.length(), bang)
                    )
                );
            }
        }
        return optional;
    }

    /**
     * Writes an input stream to a file.
     * @param input The input stream
     * @param target The target file
     * @throws IOException If there is an I/O error
     */
    private void writeToFile(final InputStream input, final File target)
        throws IOException {
        final OutputStream output = Files.newOutputStream(target.toPath());
        final byte[] buffer = new byte[ResourceCopy.BUFFER_SIZE];
        int length = input.read(buffer);
        while (length > 0) {
            output.write(buffer, 0, length);
            length = input.read(buffer);
        }
        input.close();
        output.close();
    }

}