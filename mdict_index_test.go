package mdx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeMDDKey(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `\accordion_concertina.jpg`, NormalizeMDDKey("accordion_concertina.jpg"))
	assert.Equal(t, `\nested\example.css`, NormalizeMDDKey("nested/example.css"))
	assert.Equal(t, `\already\ok.png`, NormalizeMDDKey(`\already\ok.png`))
}

func TestExtractResourceRefs(t *testing.T) {
	t.Parallel()

	content := []byte(`<head><link href="oalecd9.css"><script src="oalecd9.js"></script></head><img src="thumb_accordion.jpg"><audio src="snd://accordion__gb_1.spx"></audio><img src="thumb_accordion.jpg">`)
	refs := ExtractResourceRefs(content)

	assert.Equal(t, []string{
		"oalecd9.css",
		"oalecd9.js",
		"thumb_accordion.jpg",
		"snd://accordion__gb_1.spx",
	}, refs)
}

func TestExtractResourceRefs_SoundProtocol(t *testing.T) {
	t.Parallel()

	content := []byte(`<audio src="sound://apple.snd"></audio>`)
	refs := ExtractResourceRefs(content)
	assert.Equal(t, []string{"sound://apple.snd"}, refs)
}

func TestIsResourceRef_Protocols(t *testing.T) {
	t.Parallel()

	assert.True(t, IsResourceRef("snd://apple.spx"))
	assert.True(t, IsResourceRef("sound://apple.snd"))
	assert.True(t, IsResourceRef("file://images/thumb_apple.jpg"))
	assert.False(t, IsResourceRef("entry://apple"))
	assert.False(t, IsResourceRef("mdxentry://apple"))
	assert.False(t, IsResourceRef("dict://apple"))
}

func TestRewriteEntryResourceURLs(t *testing.T) {
	t.Parallel()

	content := []byte(`<link href="oalecd9.css"><img src="thumb_accordion.jpg"><audio src="snd://accordion__gb_1.spx"></audio><a href="help:phonetics">help</a>`)
	rewritten := string(RewriteEntryResourceURLs(content, "/assets"))

	assert.Contains(t, rewritten, `href="/assets/oalecd9.css"`)
	assert.Contains(t, rewritten, `src="/assets/thumb_accordion.jpg"`)
	assert.Contains(t, rewritten, `src="/assets/snd:%2F%2Faccordion__gb_1.spx"`)
	assert.Contains(t, rewritten, `href="help:phonetics"`)
}

func TestRewriteEntryAudioLinks_SoundScheme(t *testing.T) {
	t.Parallel()

	content := []byte(`<div><a class="audio" href="sound://ability__gb_1.spx">Play</a></div>`)
	rewritten := string(RewriteEntryAudioLinks(content, "/assets"))

	assert.Contains(t, rewritten, `<audio controls src="/assets/sound:%2F%2Fability__gb_1.spx">Play</audio>`)
	assert.NotContains(t, rewritten, `<a class="audio"`)
}

func TestRewriteEntryAudioLinks_SndScheme(t *testing.T) {
	t.Parallel()

	content := []byte(`<div><a href="snd://ability__gb_1.spx"><span>Play</span></a><a href="entry://ability">entry</a></div>`)
	rewritten := string(RewriteEntryAudioLinks(content, "/assets"))

	assert.Contains(t, rewritten, `<audio controls src="/assets/snd:%2F%2Fability__gb_1.spx"><span>Play</span></audio>`)
	assert.Contains(t, rewritten, `<a href="entry://ability">entry</a>`)
}

func TestRewriteEntryAudioLinks_RewrittenAssetURL(t *testing.T) {
	t.Parallel()

	content := []byte(`<div><a href="/assets/snd:%2F%2Fability__gb_1.spx">🔊</a></div>`)
	rewritten := string(RewriteEntryAudioLinks(content, "/assets"))

	assert.Contains(t, rewritten, `<audio controls src="/assets/snd:%2F%2Fability__gb_1.spx">🔊</audio>`)
}

func TestRewriteEntryInternalLinks(t *testing.T) {
	t.Parallel()

	content := []byte(`<a href="entry://entry://apple">apple</a><a href="entry://#frag">frag</a><a href="help:phonetics">help</a>`)
	rewritten := string(RewriteEntryInternalLinks(content))

	assert.Contains(t, rewritten, `href="entry://apple"`)
	assert.Contains(t, rewritten, `href="#frag"`)
	assert.Contains(t, rewritten, `href="help:phonetics"`)
}

func TestAssetLookupCandidates(t *testing.T) {
	t.Parallel()

	imageCandidates := AssetLookupCandidates("accordion_concertina.jpg")
	assert.Contains(t, imageCandidates, "accordion_concertina.jpg")
	assert.Contains(t, imageCandidates, `\accordion_concertina.jpg`)

	audioCandidates := AssetLookupCandidates("snd://ability__gb_1.spx")
	assert.Contains(t, audioCandidates, "snd://ability__gb_1.spx")
	assert.Contains(t, audioCandidates, "ability__gb_1.spx")

	soundCandidates := AssetLookupCandidates("sound://apple.snd")
	assert.Contains(t, soundCandidates, "sound://apple.snd")
	assert.Contains(t, soundCandidates, "snd://apple.snd")
	assert.Contains(t, soundCandidates, "apple.snd")

	fileCandidates := AssetLookupCandidates("file://images/thumb_apple.jpg")
	assert.Contains(t, fileCandidates, "file://images/thumb_apple.jpg")
	assert.Contains(t, fileCandidates, "images/thumb_apple.jpg")
	assert.Contains(t, fileCandidates, `\images\thumb_apple.jpg`)
}

func TestMemoryIndexStore(t *testing.T) {
	t.Parallel()

	store := NewMemoryIndexStore()
	info := DictionaryInfo{Name: "demo"}
	entries := []IndexEntry{
		{Keyword: "ability"},
		{Keyword: "able"},
		{Keyword: `\accordion_concertina.jpg`, NormalizedKeyword: `\accordion_concertina.jpg`, IsResource: true},
	}

	require.NoError(t, store.Put(info, entries))

	entry, err := store.GetExact("demo", "ability")
	require.NoError(t, err)
	assert.Equal(t, "ability", entry.Keyword)

	matches, err := store.PrefixSearch("demo", "ab", 10)
	require.NoError(t, err)
	require.Len(t, matches, 2)

	_, err = store.GetExact("demo", "missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIndexMiss))
}

func TestDictionaryInfoAndExportIndexIntegration(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDXPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	info := dict.DictionaryInfo()
	assert.Equal(t, "牛津高阶英汉双解词典（第9版）", info.Title)
	assert.False(t, info.IsMDD)
	assert.True(t, info.EntryCount > 0)

	entries, err := dict.ExportIndex()
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	var ability IndexEntry
	found := false
	for _, entry := range entries {
		if entry.Keyword == fixtureSampleMDXWord {
			ability = entry
			found = true
			break
		}
	}
	require.True(t, found, "expected exported index to contain %q", fixtureSampleMDXWord)

	definition, err := dict.Resolve(ability)
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(string(definition)), fixtureSampleMDXWord)

	refs := ExtractResourceRefs(definition)
	assert.Contains(t, refs, "oalecd9.css")
	assert.Contains(t, refs, "snd://ability__gb_1.spx")

	entriesOnly, err := dict.ExportEntries()
	require.NoError(t, err)
	assert.Len(t, entriesOnly, len(entries))

	rewritten, err := LookupAndRewriteHTML(dict, fixtureSampleMDXWord, "/assets")
	require.NoError(t, err)
	assert.Contains(t, string(rewritten), `/assets/oalecd9.css`)
	assert.Contains(t, string(rewritten), `<audio controls src="/assets/snd:%2F%2Fability__gb_1.spx">`)
	assert.NotContains(t, string(rewritten), `entry://entry://`)
}

func TestMDDExportIndexIntegration(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDDPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	info := dict.DictionaryInfo()
	assert.True(t, info.IsMDD)
	assert.True(t, info.IsUTF16)

	entries, err := dict.ExportIndex()
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	var resource IndexEntry
	found := false
	for _, entry := range entries {
		if entry.NormalizedKeyword == NormalizeMDDKey(manifest.SampleMDDResource) {
			resource = entry
			found = true
			break
		}
	}
	require.True(t, found, "expected exported resource index to contain %q", manifest.SampleMDDResource)
	assert.True(t, resource.IsResource)

	data, err := dict.Resolve(resource)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	resourcesOnly, err := dict.ExportResources()
	require.NoError(t, err)
	assert.Len(t, resourcesOnly, len(entries))
}

func TestNewAssetHandlerIntegration(t *testing.T) {
	manifest := loadFixtureManifest(t)

	mdd, err := New(manifest.MDDPath)
	require.NoError(t, err)
	require.NoError(t, mdd.BuildIndex())

	handler := NewAssetHandler(mdd)

	req := httptest.NewRequest(http.MethodGet, "/accordion_concertina.jpg", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Body.Bytes())

	req = httptest.NewRequest(http.MethodGet, "/snd:%2F%2Fmissing-audio.spx", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestNewAssetHandlerUsesResolverForMDD(t *testing.T) {
	t.Parallel()

	mdd := &Mdict{
		MdictBase: &MdictBase{
			fileType: MdictTypeMdd,
			meta:     &mdictMeta{},
		},
	}
	mdd.assetResolver = NewAssetResolver(nil, WithAssetSource(fakeAssetSource{assets: map[string][]byte{
		"audio/test.spx": []byte("resolver-audio"),
	}}))

	handler := NewAssetHandler(mdd)

	req := httptest.NewRequest(http.MethodGet, "/sound:%2F%2Faudio%2Ftest.spx", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []byte("resolver-audio"), rec.Body.Bytes())
}

func TestNewAssetHandlerSupportsRangeRequests(t *testing.T) {
	t.Parallel()

	mdd := &Mdict{
		MdictBase: &MdictBase{
			fileType: MdictTypeMdd,
			meta:     &mdictMeta{},
		},
	}
	mdd.assetResolver = NewAssetResolver(nil, WithAssetSource(fakeAssetSource{assets: map[string][]byte{
		"audio/test.spx": []byte("resolver-audio"),
	}}))

	handler := NewAssetHandler(mdd)

	req := httptest.NewRequest(http.MethodGet, "/sound:%2F%2Faudio%2Ftest.spx", nil)
	req.Header.Set("Range", "bytes=0-7")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusPartialContent, rec.Code)
	assert.Equal(t, []byte("resolver"), rec.Body.Bytes())
	assert.Contains(t, rec.Header().Get("Content-Range"), "bytes 0-7/14")
}

func TestNewAssetHandlerSetsCacheControlForSuccessfulResponses(t *testing.T) {
	t.Parallel()

	mdd := &Mdict{
		MdictBase: &MdictBase{
			fileType: MdictTypeMdd,
			meta:     &mdictMeta{},
		},
	}
	mdd.assetResolver = NewAssetResolver(nil, WithAssetSource(fakeAssetSource{assets: map[string][]byte{
		"audio/test.spx": []byte("resolver-audio"),
	}}))

	handler := NewAssetHandler(mdd)

	req := httptest.NewRequest(http.MethodGet, "/sound:%2F%2Faudio%2Ftest.spx", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))
}
