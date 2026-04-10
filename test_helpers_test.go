package mdx

import (
	"os"
	"path/filepath"
	"testing"
)

const defaultFixtureDir = "/home/czyt/Downloads/牛津高阶英汉双解词典（第9版）- 带高清版图片"

const (
	fixtureSampleMDXWord      = "ability"
	fixtureMissingMDXWord     = "nonexistent-xyz-123"
	fixtureSampleMDDResource  = "accordion_concertina.jpg"
	fixtureMissingMDDResource = "missing-nope.jpg"
)

type fixtureManifest struct {
	Dir                string
	MDXPath            string
	MDDPath            string
	SampleMDXWord      string
	MissingMDXWord     string
	SampleMDDResource  string
	MissingMDDResource string
}

func loadFixtureManifest(t *testing.T) fixtureManifest {
	t.Helper()

	dir := os.Getenv("MDX_TESTDICT_DIR")
	if dir == "" {
		dir = defaultFixtureDir
	}

	manifest := fixtureManifest{
		Dir:                dir,
		MDXPath:            filepath.Join(dir, "牛津高阶英汉双解词典（第9版）.mdx"),
		MDDPath:            filepath.Join(dir, "牛津高阶英汉双解词典（第9版）.mdd"),
		SampleMDXWord:      fixtureSampleMDXWord,
		MissingMDXWord:     fixtureMissingMDXWord,
		SampleMDDResource:  fixtureSampleMDDResource,
		MissingMDDResource: fixtureMissingMDDResource,
	}

	if _, err := os.Stat(manifest.MDXPath); err != nil {
		t.Skipf("skipping external fixture test: missing mdx fixture %q: %v", manifest.MDXPath, err)
	}
	if _, err := os.Stat(manifest.MDDPath); err != nil {
		t.Skipf("skipping external fixture test: missing mdd fixture %q: %v", manifest.MDDPath, err)
	}

	return manifest
}
