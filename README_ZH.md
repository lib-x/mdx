# MDX/MDD Parser for Go
[EN](README.md)

这是一个使用 Go 语言编写的高性能 MDict (.mdx/.mdd) 文件解析库。它支持查询词典内容、获取词典元信息，并提供了符合 `io/fs.FS` 接口的文件系统封装，方便与其他 Go 生态库（如 HTTP 服务器）集成。

该库最初基于 [terasum/medict](https://github.com/terasum/medict) 项目，并在其基础上进行了大量的 bug 修复、性能优化和代码重构。

## 特性

- **高性能查询**: 在 `BuildIndex()` 后构建内存精确匹配索引，提供稳定快速的词条查询。
- **MDX/MDD 支持**: 同时支持 .mdx（文本词典）和 .mdd（资源文件）格式。
- **标准接口**: 实现 `io/fs.FS` 接口，可以轻松地将词典作为文件系统提供服务。
- **健壮的错误处理**: 完善的错误处理和日志记录。
- **完整的元信息**: 提供访问词典所有元数据（如标题、描述、创建日期等）的 API。

## 安装

```bash
go get github.com/lib-x/mdx
```
*(注意: 请将 `github.com/lib-x/mdx` 替换为实际的仓库路径)*

## 用法示例

### 示例 1: 查询 MDX 词典

下面是一个如何加载 MDX 词典并查询单词的简单示例。

```go
package main

import (
	"fmt"
	"log"

	"github.com/lib-x/mdx" // 假设模块路径为此
)

func main() {
	// 1. 创建一个新的 Mdict 实例
	// 将 "path/to/your/dictionary.mdx" 替换为你的 MDX 文件路径
	mdict, err := mdx.New("path/to/your/dictionary.mdx")
	if err != nil {
		log.Fatalf("无法加载词典文件: %v", err)
	}

	// 2. 构建索引（建议在程序启动时执行一次）
	err = mdict.BuildIndex()
	if err != nil {
		log.Fatalf("无法构建词典索引: %v", err)
	}

	// 3. 打印词典信息
	fmt.Printf("词典名称: %s\n", mdict.Title())
	fmt.Printf("词典描述: %s\n", mdict.Description())

	// 4. 查询一个单词
	word := "hello"
	definition, err := mdict.Lookup(word)
	if err != nil {
		log.Fatalf("查询单词 '%s' 失败: %v", word, err)
	}

	fmt.Printf("'%s' 的释义:\n%s\n", word, string(definition))

	// 5. 查询一个不存在的单词
	word = "nonexistentword"
	_, err = mdict.Lookup(word)
	if err != nil {
		fmt.Printf("查询一个不存在的单词 '%s' 时按预期出错: %v\n", word, err)
	}
}
```

### 示例 1.1: 导出外部索引

如果你想把索引存到 Redis、SQL 或其他外部系统，可以先导出索引条目；之后再把某条索引取回来并回查真实正文。

```go
package main

import (
	"fmt"
	"log"

	"github.com/lib-x/mdx"
)

func main() {
	dict, err := mdx.New("path/to/your/dictionary.mdx")
	if err != nil {
		log.Fatal(err)
	}
	if err := dict.BuildIndex(); err != nil {
		log.Fatal(err)
	}

	info := dict.DictionaryInfo()
	fmt.Printf("title=%s entries=%d\n", info.Title, info.EntryCount)

	entries, err := dict.ExportIndex()
	if err != nil {
		log.Fatal(err)
	}

	// 在这里把 entries 存到 Redis / 数据库。
	first := entries[0]

	content, err := dict.Resolve(first)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("resolved %q -> %d bytes\n", first.Keyword, len(content))
}
```

### 示例 1.2: 显式拆分词条索引和资源索引

```go
mdxDict, _ := mdx.New("path/to/dictionary.mdx")
_ = mdxDict.BuildIndex()
entries, _ := mdxDict.ExportEntries()

mddDict, _ := mdx.New("path/to/dictionary.mdd")
_ = mddDict.BuildIndex()
resources, _ := mddDict.ExportResources()

fmt.Println(len(entries), len(resources))
```

### 示例 1.3: 将导出的索引存入外部存储

库现在提供了一个最小的 `IndexStore` 边界。你可以自己实现 Redis、SQL 或其他后端适配。仓库内也附带了一个小型内存实现：

```go
store := mdx.NewMemoryIndexStore()

info := dict.DictionaryInfo()
entries, _ := dict.ExportEntries()
_ = store.Put(info, entries)

entry, _ := store.GetExact(info.Name, "ability")
content, _ := dict.Resolve(entry)
fmt.Println(len(content))
```

### 示例 2: 列出 MDD 资源文件

MDD 文件通常包含音频、图片等资源。下面的示例展示了如何列出 MDD 文件中的所有资源。

```go
package main

import (
	"fmt"
	"log"

	"github.com/lib-x/mdx" // 假设模块路径为此
)

func main() {
	// 1. 加载 MDD 文件
	// 将 "path/to/your/resource.mdd" 替换为你的 MDD 文件路径
	mdd, err := mdx.New("path/to/your/resource.mdd")
	if err != nil {
		log.Fatalf("无法加载 MDD 文件: %v", err)
	}

	// 2. 构建索引
	err = mdd.BuildIndex()
	if err != nil {
		log.Fatalf("无法构建 MDD 索引: %v", err)
	}

	// 3. 获取并打印所有关键字条目（在 MDD 中，这通常是文件路径）
	entries, err := mdd.GetKeyWordEntries()
	if err != nil {
		log.Fatalf("无法获取关键字条目: %v", err)
	}

	fmt.Printf("在 '%s' 中找到 %d 个资源文件:\n", mdd.Name(), len(entries))
	for i, entry := range entries {
		// 只打印前 10 个作为示例
		if i >= 10 {
			break
		}
		fmt.Println(entry.KeyWord) // KeyWord 字段存储了资源的文件路径
	}
}
```

### 示例 3: 从 MDX 正文中提取资源引用

MDX 词条正文里通常会引用 CSS、JavaScript、图片、音频等资源，而这些资源通常保存在配套的 MDD 文件中。

```go
definition, err := mdict.Lookup("accordion")
if err != nil {
	log.Fatal(err)
}

refs := mdx.ExtractResourceRefs(definition)
for _, ref := range refs {
	fmt.Println(ref)
}

fmt.Println(mdx.NormalizeMDDKey("accordion_concertina.jpg"))
// 输出: \accordion_concertina.jpg
```

### 示例 4: 在 Go HTTP 中同时服务 MDX HTML 和 MDD 资源

```go
package main

import (
	"log"
	"net/http"

	"github.com/lib-x/mdx"
)

func main() {
	mdxDict, err := mdx.New("path/to/dictionary.mdx")
	if err != nil {
		log.Fatal(err)
	}
	if err := mdxDict.BuildIndex(); err != nil {
		log.Fatal(err)
	}

	mddDict, err := mdx.New("path/to/dictionary.mdd")
	if err != nil {
		log.Fatal(err)
	}
	if err := mddDict.BuildIndex(); err != nil {
		log.Fatal(err)
	}

	http.Handle("/assets/", http.StripPrefix("/assets/", mdx.NewAssetHandler(mddDict)))

	http.HandleFunc("/entry", func(w http.ResponseWriter, r *http.Request) {
		word := r.URL.Query().Get("word")
		content, err := mdx.LookupAndRewriteHTML(mdxDict, word, "/assets")
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(content)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

`LookupAndRewriteHTML` 会把如下引用改写成浏览器可直接访问的 URL：
- `oalecd9.css` -> `/assets/oalecd9.css`
- `thumb_accordion.jpg` -> `/assets/thumb_accordion.jpg`
- `snd://ability__gb_1.spx` -> `/assets/snd:%2F%2Fability__gb_1.spx`

仓库中还提供了一个可直接运行的示例：`examples/http-server`

```bash
go run ./examples/http-server \
  --mdx /path/to/dictionary.mdx \
  --mdd /path/to/dictionary.mdd \
  --listen :8080
```

另外还提供了 Redis 版联动示例：

```bash
go run ./examples/http-server-redis \
  --mdx /path/to/dictionary.mdx \
  --mdd /path/to/dictionary.mdd \
  --redis 127.0.0.1:6379 \
  --listen :8080
```

## 贡献

欢迎提交问题（Issues）和拉取请求（Pull Requests）。

## 本地夹具测试

真实 `.mdx` / `.mdd` 词典文件**不会**存放到本仓库中。

可以通过设置 `MDX_TESTDICT_DIR` 指向本地外部词典目录来运行集成测试，例如：

```bash
MDX_TESTDICT_DIR="/path/to/local/dictionary-dir" go test ./... -run "TestIntegration|TestMdict|TestMdictFS" -v
```

如果本地没有这些夹具，相关集成测试会自动 `skip`。

## 许可

本项目基于 [GNU General Public License v3.0](LICENSE) 授权。

## 模糊搜索

现在已经提供第一版内存参考实现 `MemoryFuzzyIndexStore`，适合测试和演示；生产环境的模糊搜索仍建议放在外部存储或搜索服务中。

## 多词典管理层

现在提供了一个多词典注册层，适用于一个目录中放置很多 `.mdx` / `.mdd` 配对文件的场景。

核心 API：
- `ScanDirectory(root string)`
- `DictionaryRegistry`
- `OpenDictionary(id string)`
- `LibrarySearch(query, limit)`

可运行示例：

```bash
go run ./examples/http-library --root /path/to/dictionaries --listen :8080
```

路由：
- `/dict/{id}/entry?word=...`
- `/dict/{id}/assets/...`
- `/library/search?q=...`
