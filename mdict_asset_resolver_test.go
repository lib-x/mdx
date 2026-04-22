package mdx

import (
	"encoding/binary"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestAssetResolverReadFallsBackToSidecarFS(t *testing.T) {
	t.Parallel()

	resolver := NewAssetResolver(nil, WithAssetSidecarFS(fstest.MapFS{
		"images/thumb_apple.jpg": &fstest.MapFile{Data: []byte("apple-image")},
	}))

	data, err := resolver.Read("file://images/thumb_apple.jpg")
	require.NoError(t, err)
	require.Equal(t, []byte("apple-image"), data)
}

func TestAssetResolverReadResolvesSoundSchemeFromSidecarFS(t *testing.T) {
	t.Parallel()

	resolver := NewAssetResolver(nil, WithAssetSidecarFS(fstest.MapFS{
		"audio/uk/pronunciation.spx": &fstest.MapFile{Data: []byte("spx-audio")},
	}))

	data, err := resolver.Read("sound://audio/uk/pronunciation.spx")
	require.NoError(t, err)
	require.Equal(t, []byte("spx-audio"), data)
}

func TestAssetResolverReadFollowsUTF16LinkRedirectInSidecarFS(t *testing.T) {
	t.Parallel()

	resolver := NewAssetResolver(nil, WithAssetSidecarFS(fstest.MapFS{
		"audio/link.spx": &fstest.MapFile{Data: mdictUTF16Redirect("audio/real.spx")},
		"audio/real.spx": &fstest.MapFile{Data: []byte("real-audio")},
	}))

	data, err := resolver.Read("sound://audio/link.spx")
	require.NoError(t, err)
	require.Equal(t, []byte("real-audio"), data)
}

func TestAssetResolverReadPrefersEarlierSources(t *testing.T) {
	t.Parallel()

	resolver := NewAssetResolver(nil,
		WithAssetSource(fakeAssetSource{assets: map[string][]byte{
			"audio/test.spx": []byte("sidecar-audio"),
		}}),
		WithAssetSource(fakeAssetSource{assets: map[string][]byte{
			"audio/test.spx": []byte("mdd-audio"),
		}}),
	)

	data, err := resolver.Read("sound://audio/test.spx")
	require.NoError(t, err)
	require.Equal(t, []byte("sidecar-audio"), data)
}

func TestAssetResolverReadFallsBackAcrossOrderedSources(t *testing.T) {
	t.Parallel()

	resolver := NewAssetResolver(nil,
		WithAssetSource(fakeAssetSource{}),
		WithAssetSource(fakeAssetSource{assets: map[string][]byte{
			"audio/test.spx": []byte("volume-2-audio"),
		}}),
	)

	data, err := resolver.Read("sound://audio/test.spx")
	require.NoError(t, err)
	require.Equal(t, []byte("volume-2-audio"), data)
}

func TestAssetResolverReadMissingReturnsNotExist(t *testing.T) {
	t.Parallel()

	resolver := NewAssetResolver(nil)

	_, err := resolver.Read("missing.css")
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func mdictUTF16Redirect(target string) []byte {
	prefix := []byte{'@', 0, '@', 0, '@', 0, 'L', 0, 'I', 0, 'N', 0, 'K', 0, '=', 0}
	body := make([]byte, len([]rune(target))*2)
	for i, r := range []rune(target) {
		binary.LittleEndian.PutUint16(body[i*2:], uint16(r))
	}
	return append(prefix, body...)
}

type fakeAssetSource struct {
	assets map[string][]byte
}

func (f fakeAssetSource) ReadAsset(ref string) ([]byte, error) {
	if f.assets == nil {
		return nil, fs.ErrNotExist
	}
	key := normalizeAssetResolverRef(ref)
	if data, ok := f.assets[key]; ok {
		return data, nil
	}
	return nil, fs.ErrNotExist
}

func TestNewAssetResolverAppendsDirectMdictSourcesAfterCustomSources(t *testing.T) {
	t.Parallel()

	resolver := NewAssetResolver(nil,
		WithAssetSource(fakeAssetSource{assets: map[string][]byte{
			"audio/first.spx": []byte("first"),
		}}),
		WithAssetMdicts(nil),
	)

	data, err := resolver.Read("sound://audio/first.spx")
	require.NoError(t, err)
	require.Equal(t, []byte("first"), data)
}
