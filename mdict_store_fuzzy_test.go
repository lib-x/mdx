package mdx

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryFuzzyIndexStore(t *testing.T) {
	t.Parallel()

	store := NewMemoryFuzzyIndexStore()
	info := DictionaryInfo{Name: "demo"}
	entries := []IndexEntry{
		{Keyword: "ability"},
		{Keyword: "able"},
		{Keyword: "zebra"},
	}

	require.NoError(t, store.Put(info, entries))

	results, err := store.Search("demo", "abiliti", 5)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "ability", results[0].Entry.Keyword)
	assert.Equal(t, "edit-distance", results[0].Source)

	results, err = store.Search("demo", "ab", 5)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "ability", results[0].Entry.Keyword)
	assert.Equal(t, "prefix", results[0].Source)

	_, err = store.Search("demo", "qqqqqq", 5)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIndexMiss))
}
