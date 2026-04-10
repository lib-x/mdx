package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	mdx "mdx"

	"github.com/redis/go-redis/v9"
)

func main() {
	mdxPath := flag.String("mdx", "", "path to dictionary .mdx")
	redisAddr := flag.String("redis", "127.0.0.1:6379", "redis address")
	flag.Parse()

	if *mdxPath == "" {
		log.Fatal("--mdx is required")
	}

	dict, err := mdx.New(*mdxPath)
	if err != nil {
		log.Fatalf("load mdx: %v", err)
	}
	if err := dict.BuildIndex(); err != nil {
		log.Fatalf("build mdx index: %v", err)
	}

	client := redis.NewClient(&redis.Options{Addr: *redisAddr})
	defer client.Close()

	store := mdx.NewRedisIndexStore(client,
		mdx.WithRedisIndexContext(context.Background()),
		mdx.WithRedisKeyPrefix("mdx:index"),
		mdx.WithRedisPrefixIndexMaxLen(8),
	)

	info := dict.DictionaryInfo()
	entries, err := dict.ExportEntries()
	if err != nil {
		log.Fatalf("export entries: %v", err)
	}
	if err := store.Put(info, entries); err != nil {
		log.Fatalf("store entries in redis: %v", err)
	}

	entry, err := store.GetExact(info.Name, "ability")
	if err != nil {
		log.Fatalf("get exact: %v", err)
	}
	content, err := dict.Resolve(entry)
	if err != nil {
		log.Fatalf("resolve entry: %v", err)
	}
	fmt.Printf("resolved %q -> %d bytes\n", entry.Keyword, len(content))

	matches, err := store.PrefixSearch(info.Name, "ab", 5)
	if err != nil {
		log.Fatalf("prefix search: %v", err)
	}
	for _, match := range matches {
		fmt.Println(match.Keyword)
	}
}
