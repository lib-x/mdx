package mdx

import (
	"bytes"
	"errors"
	"io/fs"
	"path"
	"strings"
	"time"
)

// MdictFS implements the fs.FS interface for MDX/MDD files.
type MdictFS struct {
	mdict *MdictBase // MdictBase provides access to dictionary data
}

// NewMdictFS creates a new MdictFS instance.
func NewMdictFS(mdict *MdictBase) *MdictFS {
	if mdict == nil {
		// Or handle this more gracefully depending on requirements
		panic("MdictFS: MdictBase cannot be nil")
	}
	return &MdictFS{
		mdict: mdict,
	}
}

// Open opens a file (keyword or resource) from the MDX/MDD.
func (mfs *MdictFS) Open(name string) (fs.File, error) {
	log.Debugf("MdictFS: Open called for name: '%s'", name)

	// Clean and normalize the path, similar to http.fs
	if name == "." || name == "" || strings.HasSuffix(name, "/") { // Treat as directory
		name = "." // Standardize root directory name
		// For now, only root directory is explicitly supported as a directory to open.
		// Subdirectories in MDD are not yet supported for direct Open, only via ReadDir.
		// If name is not ".", it implies a file lookup.
	}

	modTime := time.Now() // Default modification time
	if mfs.mdict.header != nil && mfs.mdict.header.CreationDate != "" {
		// Attempt to parse common MDX date formats
		parsedTime, err := time.Parse("2006-01-02", mfs.mdict.header.CreationDate)
		if err != nil {
			parsedTime, err = time.Parse("2006.01.02 15:04:05", mfs.mdict.header.CreationDate)
			if err != nil {
				// If specific parsing fails, keep time.Now() or use a fixed default MDX build time
				log.Warnf("MdictFS: Could not parse CreationDate '%s' for ModTime, using current time.", mfs.mdict.header.CreationDate)
			} else {
				modTime = parsedTime
			}
		} else {
			modTime = parsedTime
		}
	}

	if name == "." {
		log.Debugf("MdictFS: Opening root directory '.'")
		rootInfo := &MdictFileInfo{
			name:    ".",
			isDir:   true,
			modTime: modTime,
			// Size for a directory is often 0 or system-dependent.
		}
		return &MdictFile{
			fs:       mfs,
			name:     ".",
			isDir:    true,
			fileInfo: rootInfo,
		}, nil
	}

	// For files (keywords or MDD resources)
	var fileContent []byte
	var lookupErr error
	var actualName = name // The name used for lookup, might be normalized for MDD

	if mfs.mdict.fileType == MdictTypeMdd {
		log.Debugf("MdictFS: MDD file, attempting to look up resource: '%s'", name)
		// MDD resource paths are often case-insensitive and use backslashes.
		// The 'name' from fs.FS is usually forward-slashed.
		actualName = strings.ReplaceAll(name, "/", "\\")
		if !strings.HasPrefix(actualName, "\\") {
			actualName = "\\" + actualName
		}

		// This is a placeholder for efficient resource lookup in MDD.
		// Ideally, MdictBase would have a map for quick path-to-entry lookup for MDDs.
		// The current linear scan is highly inefficient for large MDDs.
		var foundEntry *MDictKeywordEntry
		entries, _ := mfs.mdict.GetKeyWordEntries() // Assuming GetKeyWordEntries is available and safe
		for _, entry := range entries {
			if strings.EqualFold(entry.KeyWord, actualName) {
				foundEntry = entry
				break
			}
		}

		if foundEntry != nil {
			log.Debugf("MdictFS: Found MDD entry for '%s' as keyword '%s'", name, foundEntry.KeyWord)
			fileContent, lookupErr = mfs.mdict.locateByKeywordEntry(foundEntry)
		} else {
			log.Debugf("MdictFS: MDD resource '%s' (normalized: '%s') not found in keyword entries.", name, actualName)
			lookupErr = fs.ErrNotExist
		}
	} else { // MDX file
		log.Debugf("MdictFS: MDX file, looking up keyword: '%s'", name)
		definitions, err := mfs.mdict.Lookup(name) // Lookup is case-sensitive by default
		if err != nil {
			// Assuming MdictBase.Lookup returns a specific error like ErrWordNotFound
			if errors.Is(err, ErrWordNotFound) { // Need to ensure ErrWordNotFound is defined and used in MdictBase
				log.Debugf("MdictFS: Keyword '%s' not found in MDX.", name)
				return nil, fs.ErrNotExist
			}
			log.Errorf("MdictFS: Error looking up keyword '%s' in MDX: %v", name, err)
			return nil, fmt.Errorf("error looking up keyword '%s': %w", name, err)
		}
		if len(definitions) == 0 { // Should ideally be covered by ErrWordNotFound
			log.Debugf("MdictFS: Keyword '%s' found but has no definitions.", name)
			return nil, fs.ErrNotExist
		}
		fileContent = []byte(definitions[0]) // Use the first definition
		lookupErr = nil
		log.Debugf("MdictFS: Found MDX keyword '%s', content length: %d", name, len(fileContent))
	}

	if lookupErr != nil {
		if errors.Is(lookupErr, fs.ErrNotExist) || strings.Contains(lookupErr.Error(), "not found") { // Heuristic
			return nil, fs.ErrNotExist
		}
		log.Errorf("MdictFS: Error retrieving content for '%s': %v", name, lookupErr)
		return nil, fmt.Errorf("error retrieving content for '%s': %w", name, lookupErr)
	}

	if fileContent == nil { // Safeguard
		log.Warnf("MdictFS: Content for '%s' is nil after successful lookup, treating as not found.", name)
		return nil, fs.ErrNotExist
	}

	fileInfo := &MdictFileInfo{
		name:    path.Base(name), // Use base name for FileInfo, as fs.FileInfo expects.
		size:    int64(len(fileContent)),
		isDir:   false,
		modTime: modTime,
	}

	return &MdictFile{
		fs:       mfs,
		name:     name, // Store the full path used to open
		isDir:    false,
		content:  fileContent,
		reader:   bytes.NewReader(fileContent),
		fileInfo: fileInfo,
	}, nil
}

// MdictFile implements fs.File for a keyword's definition or an MDD resource.
type MdictFile struct {
	fs       *MdictFS
	name     string // The name this file was opened with.
	isDir    bool
	reader   *bytes.Reader // Used for Read, Seek, ReadAt for files. Nil for directories.
	content  []byte        // Content of the file (definition or resource). Nil for directories.
	fileInfo fs.FileInfo   // Cached FileInfo.
}

// Stat returns the FileInfo structure describing the file.
func (mf *MdictFile) Stat() (fs.FileInfo, error) {
	if mf.fileInfo == nil {
		// This should ideally be initialized by Open. This is a fallback.
		log.Warnf("MdictFile.Stat: fileInfo is nil for '%s', creating default.", mf.name)
		modTime := time.Now()
		if mf.fs.mdict.header != nil && mf.fs.mdict.header.CreationDate != "" {
			parsedTime, err := time.Parse("2006-01-02", mf.fs.mdict.header.CreationDate)
			if err == nil {
				modTime = parsedTime
			}
			// Add other parsing attempts if needed
		}
		mf.fileInfo = &MdictFileInfo{
			name:    path.Base(mf.name),
			size:    int64(len(mf.content)), // Size is 0 if content is nil (e.g. for a directory file opened not via Open("."))
			isDir:   mf.isDir,
			modTime: modTime,
		}
	}
	return mf.fileInfo, nil
}

// Read reads up to len(b) bytes into b.
func (mf *MdictFile) Read(b []byte) (int, error) {
	if mf.isDir {
		log.Debugf("MdictFile.Read: Attempt to read directory '%s'", mf.name)
		return 0, &fs.PathError{Op: "read", Path: mf.name, Err: fs.ErrIsDir}
	}
	if mf.reader == nil {
		log.Warnf("MdictFile.Read: No reader available for file '%s' (possibly closed or not a regular file).", mf.name)
		return 0, &fs.PathError{Op: "read", Path: mf.name, Err: fs.ErrClosed} // fs.ErrClosed is a reasonable guess
	}
	return mf.reader.Read(b)
}

// Close closes the file. For MdictFile, this means releasing the byte slice and reader.
func (mf *MdictFile) Close() error {
	log.Debugf("MdictFile.Close: Closing file '%s'", mf.name)
	mf.reader = nil
	mf.content = nil  // Allow GC
	mf.fileInfo = nil // Invalidate cached FileInfo
	return nil
}

// Seek sets the offset for the next Read or Write on file to offset, interpreted
// according to whence: 0 means relative to the origin of the file, 1 means
// relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error, if any.
func (mf *MdictFile) Seek(offset int64, whence int) (int64, error) {
	if mf.isDir {
		return 0, &fs.PathError{Op: "seek", Path: mf.name, Err: fs.ErrIsDir}
	}
	if mf.reader == nil {
		return 0, &fs.PathError{Op: "seek", Path: mf.name, Err: fs.ErrClosed}
	}
	return mf.reader.Seek(offset, whence)
}

// MdictFileInfo implements fs.FileInfo.
type MdictFileInfo struct {
	name    string
	size    int64
	isDir   bool
	modTime time.Time
}

func (mfi *MdictFileInfo) Name() string       { return mfi.name }
func (mfi *MdictFileInfo) Size() int64        { return mfi.size }
func (mfi *MdictFileInfo) IsDir() bool        { return mfi.isDir }
func (mfi *MdictFileInfo) ModTime() time.Time { return mfi.modTime }
func (mfi *MdictFileInfo) Sys() interface{}   { return nil }

// Mode returns the file mode bits.
func (mfi *MdictFileInfo) Mode() fs.FileMode {
	if mfi.isDir {
		return fs.ModeDir | 0555 // r-xr-xr-x (directory)
	}
	return 0444 // r--r--r-- (regular file, read-only)
}

// Ensure MdictFile implements fs.File and io.ReadSeeker (via bytes.Reader).
var _ fs.File = (*MdictFile)(nil)
var _ fs.ReadDirFile = (*MdictFile)(nil) // ReadDir will be added next

// Ensure MdictFS implements fs.FS
var _ fs.FS = (*MdictFS)(nil)

// ReadDir reads the contents of the directory.
// For MdictFS, this is only implemented for the root directory ".".
func (mf *MdictFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !mf.isDir || mf.name != "." {
		log.Warnf("ReadDir called on non-root or non-directory MdictFile: %s", mf.name)
		return nil, &fs.PathError{Op: "readdir", Path: mf.name, Err: errors.New("not a directory or not root")}
	}

	log.Debugf("ReadDir called for MdictFS root: %s", mf.fs.mdict.filePath)

	// For the root directory, list all keywords/resources as DirEntry items.
	// This could be very large. `n` parameter is for batching but often ignored by simple impls.
	// We'll fetch all and then slice if n > 0.

	// This assumes GetKeyWordEntries returns all "files" at the root for MDX
	// or all resource paths for MDD.
	// For MDD, paths might have subdirectories (e.g., \sound\foo.spx).
	// A simple approach is to list all unique first-level path components as directories,
	// and all full paths as files. This can get complex.
	// For now, let's list all keywords/paths as files in the root.

	keywords, err := mf.fs.mdict.GetKeyWordEntries()
	if err != nil {
		log.Errorf("ReadDir: Error getting keyword entries for %s: %v", mf.fs.mdict.filePath, err)
		return nil, fmt.Errorf("could not get keyword entries: %w", err)
	}

	modTime := time.Now() // Default mod time for entries
	if mf.fs.mdict.header != nil && mf.fs.mdict.header.CreationDate != "" {
		// Attempt to parse common MDX date formats
		parsedTime, ptErr := time.Parse("2006-01-02", mf.fs.mdict.header.CreationDate)
		if ptErr == nil {
			modTime = parsedTime
		} else {
			parsedTime, ptErr = time.Parse("2006.01.02 15:04:05", mf.fs.mdict.header.CreationDate)
			if ptErr == nil {
				modTime = parsedTime
			}
		}
	}


	entries := make([]fs.DirEntry, 0, len(keywords))
	for _, kw := entry {
		// For MDD, keywords might be paths like \SOUND\BELL.SPX
		// For fs.DirEntry, Name() should be the base name.
		entryName := kw.KeyWord
		isDir := false // Assume all keywords are files unless we parse paths

		if mf.fs.mdict.fileType == MdictTypeMdd {
			entryName = strings.TrimLeft(kw.KeyWord, "\\/")
			// If entryName still contains path separators, it implies a structure.
			// However, fs.ReadDir lists entries at the current level.
			// A full fs.Sub / walking FS would need more complex path handling.
			// For now, we list all MDD keywords as files at the root.
			// A more advanced implementation might create virtual directories.
		}
		
		// We don't have individual file sizes without looking them up,
		// which is too expensive for ReadDir. fs.FileInfo returned by DirEntry.Info()
		// can provide it, but DirEntry itself can return a simplified FileInfo.
		// Size is often set to 0 for ReadDir results if not readily available.
		
		// To get the actual size, we'd need to "Open" and "Stat" each file, which is not performant here.
		// So, MdictDirEntry will likely return a FileInfo with size 0 or an estimated size.
		// For now, let's create a MdictFileInfo that might have 0 size.
		// The Stat() method on the *opened* MdictFile will have the correct size.
		
		dirEntryInfo := &MdictFileInfo{
			name:    path.Base(entryName), // Base name for DirEntry
			size:    0,                    // Size is typically 0 or unknown for ReadDir entries
			isDir:   isDir,
			modTime: modTime,
		}
		entries = append(entries, dirEntryInfo) // MdictFileInfo implements fs.DirEntry via fs.FileInfo
	}

	// Handle 'n' parameter for batching if desired, though many fs.FS impls ignore it for simplicity.
	if n > 0 && n < len(entries) {
		entries = entries[:n]
	}
	// If n <= 0, return all entries. If n > 0 and all entries are returned, return io.EOF.
	// This part is tricky. Most simple FS implementations return all and then io.EOF next call if n was > 0.
	// Or just return all if n <= 0.
	// For now, if n > 0 and we returned fewer than requested (i.e. all of them), no EOF.
	// If n > 0 and we returned n entries, and there are more, no EOF.
	// If n > 0 and we returned all entries and that's less than n, no EOF.
	// The common contract is to return io.EOF when no more entries are available.
	// This simple implementation returns all entries in one go.
	// A stateful MdictFile would be needed to handle 'n' correctly over multiple calls.
	// For now, this is a non-batching ReadDir.
	// A truly stateful ReadDir would store the current offset in mf.keywordsRead
	// and return slices. For simplicity, we return all.
	// If we return all entries, and n > 0, subsequent calls with n > 0 should yield io.EOF.
	// This is not handled here yet.

	log.Debugf("ReadDir for '%s' returning %d entries", mf.name, len(entries))
	return entries, nil // Return nil error, not io.EOF, if entries are returned.
}
