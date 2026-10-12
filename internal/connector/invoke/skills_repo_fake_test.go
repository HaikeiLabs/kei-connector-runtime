package invoke

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeSkillsGitHub serves the GitHub REST reads the contract's skills_repo
// backend makes for https://github.com/acme/skills at ref main: the commit,
// the git trees, and raw blobs. Every request must carry token.
type fakeSkillsGitHub struct {
	t     *testing.T
	token string

	mu    sync.Mutex
	calls int
	paths []string

	commit, root, folder string
	trees                map[string][]fakeTreeEntry // sha -> non-recursive entries
	recursive            map[string][]fakeTreeEntry // sha -> recursive entries
	blobs                map[string][]byte
}

type fakeTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size,omitempty"`
}

func fakeSHA(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])[:40]
}

// newFakeSkillsGitHub builds the repository from skills: skill name -> file
// path inside the skill folder -> content. Skills live under skills/.
func newFakeSkillsGitHub(t *testing.T, token string, skills map[string]map[string][]byte) *fakeSkillsGitHub {
	f := &fakeSkillsGitHub{
		t: t, token: token, commit: fakeSHA("commit"), root: fakeSHA("root"), folder: fakeSHA("tree:skills"),
		trees: map[string][]fakeTreeEntry{}, recursive: map[string][]fakeTreeEntry{}, blobs: map[string][]byte{},
	}
	f.trees[f.root] = []fakeTreeEntry{{Path: "skills", Mode: "040000", Type: "tree", SHA: f.folder}}
	names := make([]string, 0, len(skills))
	for name := range skills {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		skillTree := fakeSHA("tree:" + name)
		f.trees[f.folder] = append(f.trees[f.folder], fakeTreeEntry{Path: name, Mode: "040000", Type: "tree", SHA: skillTree})
		f.recursive[f.folder] = append(f.recursive[f.folder], fakeTreeEntry{Path: name, Mode: "040000", Type: "tree", SHA: skillTree})
		dirs := map[string]bool{}
		files := make([]string, 0, len(skills[name]))
		for p := range skills[name] {
			files = append(files, p)
		}
		sort.Strings(files)
		for _, p := range files {
			for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
				if !dirs[dir] {
					dirs[dir] = true
					entry := fakeTreeEntry{Path: dir, Mode: "040000", Type: "tree", SHA: fakeSHA("tree:" + name + "/" + dir)}
					f.recursive[skillTree] = append(f.recursive[skillTree], entry)
					entry.Path = name + "/" + dir
					f.recursive[f.folder] = append(f.recursive[f.folder], entry)
				}
			}
			content := skills[name][p]
			blob := fakeSHA("blob:" + name + "/" + p)
			f.blobs[blob] = content
			entry := fakeTreeEntry{Path: p, Mode: "100644", Type: "blob", SHA: blob, Size: int64(len(content))}
			f.recursive[skillTree] = append(f.recursive[skillTree], entry)
			entry.Path = name + "/" + p
			f.recursive[f.folder] = append(f.recursive[f.folder], entry)
		}
	}
	return f
}

func (f *fakeSkillsGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls++
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	if r.Method != http.MethodGet {
		f.t.Errorf("skills repo request method = %s", r.Method)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+f.token {
		f.t.Errorf("skills repo authorization = %q", got)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/repos/acme/skills/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case rest == "commits/main":
		writeFakeJSON(w, map[string]any{"sha": f.commit, "commit": map[string]any{"tree": map[string]any{"sha": f.root}}})
	case strings.HasPrefix(rest, "git/trees/"):
		sha := strings.TrimPrefix(rest, "git/trees/")
		entries, found := f.trees[sha]
		if r.URL.Query().Get("recursive") == "1" {
			entries, found = f.recursive[sha]
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		writeFakeJSON(w, map[string]any{"sha": sha, "truncated": false, "tree": entries})
	case strings.HasPrefix(rest, "git/blobs/"):
		content, found := f.blobs[strings.TrimPrefix(rest, "git/blobs/")]
		if !found {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(content)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeSkillsGitHub) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func writeFakeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func skillMD(name string) []byte {
	return []byte("---\nname: " + name + "\ndescription: Deploys the demo service.\nmetadata:\n  version: 1.2.0\n  harnesses: [claude_code, codex]\n---\n# " + name + "\n")
}
