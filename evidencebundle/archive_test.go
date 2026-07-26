package evidencebundle

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestArchiveRoundTripIsDeterministic(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := ExportArchive(bundle)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExportArchive(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical bundles produced different archives")
	}

	imported, err := ImportArchive(first)
	if err != nil {
		t.Fatal(err)
	}
	if imported.Manifest.BundleRoot != bundle.Manifest.BundleRoot {
		t.Fatalf("bundle root changed: %s != %s", imported.Manifest.BundleRoot, bundle.Manifest.BundleRoot)
	}
	reexported, err := ExportArchive(imported)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, reexported) {
		t.Fatal("import and re-export changed archive bytes")
	}

	reader, err := zip.NewReader(bytes.NewReader(first), int64(len(first)))
	if err != nil {
		t.Fatal(err)
	}
	if reader.File[0].Name != ManifestEntryPath {
		t.Fatalf("manifest is not first deterministic entry: %s", reader.File[0].Name)
	}
	for _, file := range reader.File {
		if file.Method != zip.Store || !file.Modified.Equal(archiveTimestamp) {
			t.Fatalf("non-deterministic ZIP metadata for %s", file.Name)
		}
	}
}

func TestImportArchiveRejectsModifiedObject(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ExportArchive(bundle)
	if err != nil {
		t.Fatal(err)
	}
	entries := readTestArchive(t, payload)
	for name := range entries {
		if name != ManifestEntryPath {
			entries[name][0] ^= 1
			break
		}
	}
	_, err = ImportArchive(writeTestArchive(t, entries))
	if !errors.Is(err, ErrObjectDigestMismatch) {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestImportArchiveRejectsMissingAndUnexpectedEntries(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ExportArchive(bundle)
	if err != nil {
		t.Fatal(err)
	}
	entries := readTestArchive(t, payload)
	for name := range entries {
		if name != ManifestEntryPath {
			delete(entries, name)
			break
		}
	}
	if _, err = ImportArchive(writeTestArchive(t, entries)); !errors.Is(err, ErrArchiveEntryMismatch) {
		t.Fatalf("expected missing entry rejection, got %v", err)
	}

	entries = readTestArchive(t, payload)
	entries["unexpected.json"] = []byte(`{}`)
	if _, err = ImportArchive(writeTestArchive(t, entries)); !errors.Is(err, ErrArchiveEntryMismatch) {
		t.Fatalf("expected unexpected entry rejection, got %v", err)
	}
}

func TestImportArchiveRejectsUnsafeDuplicateAndCompressedEntries(t *testing.T) {
	assertInvalidTestArchive(t, []testArchiveEntry{
		{name: ManifestEntryPath, payload: []byte(`{}`), method: zip.Store},
		{name: "../escape.json", payload: []byte(`{}`), method: zip.Store},
	})
	assertInvalidTestArchive(t, []testArchiveEntry{
		{name: ManifestEntryPath, payload: []byte(`{}`), method: zip.Store},
		{name: ManifestEntryPath, payload: []byte(`{}`), method: zip.Store},
	})
	assertInvalidTestArchive(t, []testArchiveEntry{
		{name: ManifestEntryPath, payload: []byte(`{}`), method: zip.Deflate},
	})
}

func TestExportArchiveRejectsUnverifiedBundle(t *testing.T) {
	bundle, err := Build(bundleFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	bundle.Manifest.BundleRoot = "sha256:modified"
	if _, err = ExportArchive(bundle); !errors.Is(err, ErrBundleRootMismatch) {
		t.Fatalf("expected unverified bundle rejection, got %v", err)
	}
}

type testArchiveEntry struct {
	name    string
	payload []byte
	method  uint16
}

func assertInvalidTestArchive(t *testing.T, entries []testArchiveEntry) {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range entries {
		target, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: entry.method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = target.Write(entry.payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportArchive(output.Bytes()); !errors.Is(err, ErrArchiveInvalid) {
		t.Fatalf("expected invalid archive rejection, got %v", err)
	}
}

func readTestArchive(t *testing.T, payload []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		source, openErr := file.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		entry, readErr := io.ReadAll(source)
		_ = source.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		entries[file.Name] = entry
	}
	return entries
}

func writeTestArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, payload := range entries {
		target, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = target.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
