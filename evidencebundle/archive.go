package evidencebundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

var (
	ErrArchiveInvalid       = errors.New("evidencebundle: archive is invalid")
	ErrArchiveEntryMismatch = errors.New("evidencebundle: archive entry does not match manifest")
	ErrArchiveTooLarge      = errors.New("evidencebundle: archive exceeds size limit")
)

const (
	ArchiveExtension   = ".coseb"
	ArchiveMediaType   = "application/vnd.cargoos.evidence-bundle+zip"
	ManifestEntryPath  = "manifest.json"
	SignatureEntryPath = "signature.json"
	ObjectEntryPrefix  = "objects/"
	MaxArchiveSize     = 64 << 20
	MaxArchiveEntries  = 4096
)

var archiveTimestamp = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// ExportArchive produces the portable, deterministic ZIP representation of a
// verified Evidence Bundle. Identical bundles produce byte-identical archives.
func ExportArchive(bundle Bundle) ([]byte, error) {
	entries, err := bundleArchiveEntries(bundle)
	if err != nil {
		return nil, err
	}
	return writeArchive(entries)
}

func bundleArchiveEntries(bundle Bundle) ([]archiveEntry, error) {
	if err := Verify(bundle); err != nil {
		return nil, err
	}
	manifestPayload, err := CanonicalManifest(bundle.Manifest)
	if err != nil {
		return nil, err
	}
	if len(bundle.Objects)+1 > MaxArchiveEntries {
		return nil, ErrArchiveTooLarge
	}

	entries := make([]archiveEntry, 0, len(bundle.Objects)+1)
	entries = append(entries, archiveEntry{path: ManifestEntryPath, payload: manifestPayload})
	for _, object := range bundle.Objects {
		entryPath, pathErr := objectArchivePath(object.Path)
		if pathErr != nil {
			return nil, pathErr
		}
		entries = append(entries, archiveEntry{path: entryPath, payload: bytes.Clone(object.Payload)})
	}
	return entries, nil
}

func writeArchive(entries []archiveEntry) ([]byte, error) {
	if len(entries) == 0 || len(entries) > MaxArchiveEntries {
		return nil, ErrArchiveTooLarge
	}
	entries = append([]archiveEntry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range entries {
		if int64(output.Len())+int64(len(entry.payload)) > MaxArchiveSize {
			_ = writer.Close()
			return nil, ErrArchiveTooLarge
		}
		header := &zip.FileHeader{Name: entry.path, Method: zip.Store}
		header.SetModTime(archiveTimestamp)
		header.SetMode(0o600)
		target, createErr := writer.CreateHeader(header)
		if createErr != nil {
			return nil, createErr
		}
		if _, writeErr := target.Write(entry.payload); writeErr != nil {
			return nil, writeErr
		}
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	if output.Len() > MaxArchiveSize {
		return nil, ErrArchiveTooLarge
	}
	return output.Bytes(), nil
}

// ImportArchive reads a portable .coseb archive without consulting production
// storage and verifies its manifest, Bundle Root, object list, sizes and hashes.
func ImportArchive(payload []byte) (Bundle, error) {
	entries, err := readArchive(payload)
	if err != nil {
		return Bundle{}, err
	}
	return bundleFromArchiveEntries(entries)
}

func readArchive(payload []byte) (map[string][]byte, error) {
	if len(payload) == 0 {
		return nil, ErrArchiveInvalid
	}
	if len(payload) > MaxArchiveSize {
		return nil, ErrArchiveTooLarge
	}
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrArchiveInvalid, err)
	}
	if len(reader.File) == 0 || len(reader.File) > MaxArchiveEntries {
		return nil, ErrArchiveInvalid
	}

	entries := make(map[string][]byte, len(reader.File))
	var total int64
	for _, file := range reader.File {
		if !validArchivePath(file.Name) || file.FileInfo().IsDir() || file.Method != zip.Store {
			return nil, fmt.Errorf("%w: %s", ErrArchiveInvalid, file.Name)
		}
		if _, duplicate := entries[file.Name]; duplicate {
			return nil, fmt.Errorf("%w: duplicate %s", ErrArchiveInvalid, file.Name)
		}
		if file.UncompressedSize64 > MaxArchiveSize || total+int64(file.UncompressedSize64) > MaxArchiveSize {
			return nil, ErrArchiveTooLarge
		}
		entry, readErr := readArchiveEntry(file)
		if readErr != nil {
			return nil, readErr
		}
		total += int64(len(entry))
		entries[file.Name] = entry
	}
	return entries, nil
}

func bundleFromArchiveEntries(entries map[string][]byte) (Bundle, error) {
	entries = copyArchiveEntries(entries)
	manifestPayload, exists := entries[ManifestEntryPath]
	if !exists {
		return Bundle{}, fmt.Errorf("%w: missing %s", ErrArchiveInvalid, ManifestEntryPath)
	}
	delete(entries, ManifestEntryPath)
	var manifest Manifest
	if err = json.Unmarshal(manifestPayload, &manifest); err != nil {
		return Bundle{}, fmt.Errorf("%w: manifest: %v", ErrArchiveInvalid, err)
	}
	canonical, err := CanonicalManifest(manifest)
	if err != nil || !bytes.Equal(canonical, manifestPayload) {
		return Bundle{}, fmt.Errorf("%w: manifest is not canonical", ErrArchiveInvalid)
	}
	if len(entries) != len(manifest.Objects) {
		return Bundle{}, ErrArchiveEntryMismatch
	}

	objects := make([]Object, 0, len(manifest.Objects))
	for _, descriptor := range manifest.Objects {
		entryPath, pathErr := objectArchivePath(descriptor.Path)
		if pathErr != nil {
			return Bundle{}, pathErr
		}
		objectPayload, found := entries[entryPath]
		if !found {
			return Bundle{}, fmt.Errorf("%w: missing %s", ErrArchiveEntryMismatch, entryPath)
		}
		delete(entries, entryPath)
		objects = append(objects, Object{
			Path:      descriptor.Path,
			MediaType: descriptor.MediaType,
			Payload:   objectPayload,
		})
	}
	if len(entries) != 0 {
		return Bundle{}, ErrArchiveEntryMismatch
	}
	bundle := Bundle{Manifest: manifest, Objects: objects}
	if err = Verify(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func copyArchiveEntries(source map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(source))
	for entryPath, payload := range source {
		result[entryPath] = bytes.Clone(payload)
	}
	return result
}

type archiveEntry struct {
	path    string
	payload []byte
}

func objectArchivePath(objectPath string) (string, error) {
	candidate := ObjectEntryPrefix + objectPath
	if !validArchivePath(candidate) || !strings.HasPrefix(candidate, ObjectEntryPrefix) {
		return "", ErrObjectPathInvalid
	}
	return candidate, nil
}

func validArchivePath(candidate string) bool {
	return candidate != "" &&
		candidate == strings.TrimSpace(candidate) &&
		!strings.HasPrefix(candidate, "/") &&
		!strings.Contains(candidate, "\\") &&
		path.Clean(candidate) == candidate &&
		candidate != "." &&
		!strings.HasPrefix(candidate, "../")
}

func readArchiveEntry(file *zip.File) ([]byte, error) {
	source, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrArchiveInvalid, file.Name, err)
	}
	defer source.Close()
	entry, err := io.ReadAll(io.LimitReader(source, MaxArchiveSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrArchiveInvalid, file.Name, err)
	}
	if len(entry) > MaxArchiveSize || uint64(len(entry)) != file.UncompressedSize64 {
		return nil, ErrArchiveTooLarge
	}
	return entry, nil
}
