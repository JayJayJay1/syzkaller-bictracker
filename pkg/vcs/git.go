// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bufio"
	"bytes"
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

type git struct {
	dir      string
	ignoreCC map[string]bool
	precious bool
	sandbox  bool
}

func newGit(dir string, ignoreCC map[string]bool, opts []RepoOpt) *git {
	git := &git{
		dir:      dir,
		ignoreCC: ignoreCC,
		sandbox:  true,
	}
	for _, opt := range opts {
		switch opt {
		case OptPrecious:
			git.precious = true
		case OptDontSandbox:
			git.sandbox = false
		}
	}
	return git
}

func filterEnv() []string {
	// We have to filter various git environment variables - if
	// these variables are set (e.g. if a test is being run as
	// part of a rebase) we're going to be acting on some other
	// repository (e.g the syzkaller tree itself) rather than the
	// intended repo.
	env := os.Environ()
	for i := 0; i < len(env); i++ {
		if strings.HasPrefix(env[i], "GIT_DIR") ||
			strings.HasPrefix(env[i], "GIT_WORK_TREE") ||
			strings.HasPrefix(env[i], "GIT_INDEX_FILE") ||
			strings.HasPrefix(env[i], "GIT_OBJECT_DIRECTORY") {
			env = append(env[:i], env[i+1:]...)
			i--
		}
	}

	return env
}

func (git *git) Poll(repo, branch string) (*Commit, error) {
	git.reset()
	origin, err := git.git("remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(origin)) != repo {
		// The repo is here, but it has wrong origin (e.g. repo in config has changed), re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	// Use origin/branch for the case the branch was force-pushed,
	// in such case branch is not the same is origin/branch and we will
	// stuck with the local version forever (git checkout won't fail).
	if _, err := git.git("checkout", "origin/"+branch); err != nil {
		// No such branch (e.g. branch in config has changed), re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := git.git("fetch", "--force"); err != nil {
		// Something else is wrong, re-clone.
		if err := git.clone(repo, branch); err != nil {
			return nil, err
		}
	}
	if _, err := git.git("checkout", "origin/"+branch); err != nil {
		return nil, err
	}
	if _, err := git.git("submodule", "update", "--init"); err != nil {
		return nil, err
	}
	return git.HeadCommit()
}

func (git *git) CheckoutBranch(repo, branch string) (*Commit, error) {
	if err := git.repair(); err != nil {
		return nil, err
	}
	repoHash := hash.String([]byte(repo))
	// Because the HEAD is detached, submodules assumes "origin" to be the default
	// remote when initializing.
	// This sets "origin" to be the current remote.
	// Ignore errors as we can double add or remove the same remote and that will fail.
	git.git("remote", "rm", "origin")
	git.git("remote", "add", "origin", repo)
	git.git("remote", "add", repoHash, repo)
	_, err := git.git("fetch", "--force", repoHash, branch)
	if err != nil {
		return nil, err
	}
	if _, err := git.git("checkout", "FETCH_HEAD"); err != nil {
		return nil, err
	}
	if _, err := git.git("submodule", "update", "--init"); err != nil {
		return nil, err
	}
	return git.HeadCommit()
}

func (git *git) CheckoutCommit(repo, commit string) (*Commit, error) {
	if err := git.repair(); err != nil {
		return nil, err
	}
	if err := git.fetchRemote(repo); err != nil {
		return nil, err
	}
	return git.SwitchCommit(commit)
}

func (git *git) fetchRemote(repo string) error {
	repoHash := hash.String([]byte(repo))
	// Ignore error as we can double add the same remote and that will fail.
	git.git("remote", "add", repoHash, repo)
	_, err := git.git("fetch", "--force", "--tags", repoHash)
	return err
}

func (git *git) SwitchCommit(commit string) (*Commit, error) {
	if !git.precious {
		git.git("reset", "--hard")
		git.git("clean", "-fdx")
	}
	if _, err := git.git("checkout", commit); err != nil {
		return nil, err
	}
	if _, err := git.git("submodule", "update", "--init"); err != nil {
		return nil, err
	}
	return git.HeadCommit()
}

func (git *git) ApplyPatch(commit string) error {
	availablePatchesInOrder := [5]string{"1a2383e8b84c0451fd9b1eec3b9aab16f30b597c", "8d470a45d1a65e6a308aeee5da7f5b37d3303c04", "9df918698408fd914493aba0b7858fef50eba63a", "2bb2b7b57f81255c13f4395ea911d6bdc70c9fe2", "a54df7622717a40ddec95fd98086aff8ba7839a6"}
	patchesApplicableFor := map[string]string{
		"51094a24b85e29138b7fa82ef1e1b4fe19c90046": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"7535b832c6399b5ebfc5b53af5c51dd915ee2538": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"48ea09cddae0b794cde2070f106ef676703dbcd3": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"8b05aa26336113c4cea25f1c333ee8cd4fc212a6": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"79cc1ba7badf9e7a12af99695a557e9ce27ee967": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"9360d035a579d95d1e76c471061b9065b18a0eb1": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"5d5dd3e4a86a64cc69fa0fdd32f769b1d97a9a83": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"0a64ce6e5442bbd96cbe9057d9ba1edab244f25b": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"665fe72a7d4f0ad17923e0a5ff2e6cc64d57c970": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"2852ca7fba9f77b204f0fe953b31fadd0057c936": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"51889d225ce2ce118d8413eb4282045add81a689": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"07a22b61946f0b80065b0ddcc703b715f84355f5": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"20fb0c8272bbb102d15bdd11aa64f828619dd7cc": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"38335cc5ffafa111210ad6bbe5a63a87db38ee68": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"b87f02307d3cfbda768520f0687c51ca77e14fc3": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"44d35720c9a660074b77ab9de37abf2c01c5b44f": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"537e62c865dcb9b91d07ed83f8615b71fa0b51bb": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"595b893e2087de306d0781795fb8ec47873596a6": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"2bb2b7b57f81255c13f4395ea911d6bdc70c9fe2": "2bb2b7b57f81255c13f4395ea911d6bdc70c9fe2",
		"9df918698408fd914493aba0b7858fef50eba63a": "9df918698408fd914493aba0b7858fef50eba63a",
		"f953f140f318a641c443b0b8c618155ed90a7a10": "9df918698408fd914493aba0b7858fef50eba63a",
		"8d470a45d1a65e6a308aeee5da7f5b37d3303c04": "8d470a45d1a65e6a308aeee5da7f5b37d3303c04",
		"1a2383e8b84c0451fd9b1eec3b9aab16f30b597c": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"e83a4472bf9f556d01984048e398e64246c4dd6f": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"23b36fec7e14f8cf1c17e832e53dd4761e0dfe83": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"c985aafb60e972c0a6b8d0bd65e03af5890b748a": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"93d102f094be9beab28e5afb656c188b16a3793b": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"f39650de687e35766572ac89dbcd16a5911e2f0a": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"2f31ad64a9cce8b2409d2d4563482adfb8664082": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"3f388f28639fd19d5bf6df7a882c94ccfbf49c2b": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"63037f74725ddd8a767ed2ad0369e60a3bf1f2ce": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"79076e1241bb3bf02d0aac7d39120d8161fe07b1": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"5916d5f9b3347344a3d96ba6b54cf8e290eba96a": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"60c958d8df9cfc40b745d6cd583cfbfa7525ead6": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
	}

	// Determine last commit which changed "kernel/panic.c"
	// git log --pretty=format:%H -S "kernel/panic.c" -- kernel/panic.c
	lastChangeCommit, err := git.git("log", "--pretty=format:%H", "-n", "1", "--", "kernel/panic.c")
	if err != nil {
		panic(err)
	}

	patch, ok := patchesApplicableFor[string(lastChangeCommit)]
	if !ok {
		for _, patchToTest := range availablePatchesInOrder {
			if _, err := git.git("apply", "--check", "/data/jakob.steeg-thesis/workspace/patches/"+patchToTest+".txt"); err == nil {
				fmt.Println("Applied patch " + patchToTest + " by testing all patches.\n")
				return nil
			}
		}
		panic("No patch found for commit " + commit)
	}
	fmt.Println("Applying patch " + patch + "\n")
	if _, err := git.git("apply", "/data/jakob.steeg-thesis/workspace/patches/"+patch+".txt"); err != nil {
		panic(err)
	}
	return nil
}

func (git *git) clone(repo, branch string) error {
	if git.precious {
		return fmt.Errorf("won't reinit precious repo")
	}
	if err := git.initRepo(nil); err != nil {
		return err
	}
	if _, err := git.git("remote", "add", "origin", repo); err != nil {
		return err
	}
	if _, err := git.git("fetch", "origin", branch); err != nil {
		return err
	}
	return nil
}

func (git *git) reset() error {
	// This function tries to reset git repo state to a known clean state.
	if git.precious {
		return nil
	}
	git.git("reset", "--hard")
	git.git("clean", "-fdx")
	git.git("bisect", "reset")
	_, err := git.git("reset", "--hard")
	return err
}

func (git *git) repair() error {
	if err := git.reset(); err != nil {
		return git.initRepo(err)
	}
	return nil
}

func (git *git) initRepo(reason error) error {
	if reason != nil {
		log.Logf(1, "git: initializing repo at %v: %v", git.dir, reason)
	}
	if err := os.RemoveAll(git.dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %v", err)
	}
	if err := osutil.MkdirAll(git.dir); err != nil {
		return fmt.Errorf("failed to create repo dir: %v", err)
	}
	if git.sandbox {
		if err := osutil.SandboxChown(git.dir); err != nil {
			return err
		}
	}
	if _, err := git.git("init"); err != nil {
		return err
	}
	return nil
}

func (git *git) Contains(commit string) (bool, error) {
	_, err := git.git("branch", "--contains", commit)
	return err == nil, nil
}

func (git *git) HeadCommit() (*Commit, error) {
	return git.getCommit("HEAD")
}

func (git *git) getCommit(commit string) (*Commit, error) {
	output, err := git.git("log", "--format=%H%n%s%n%ae%n%an%n%ad%n%P%n%cd%n%b", "-n", "1", commit)
	if err != nil {
		return nil, err
	}
	return gitParseCommit(output, nil, nil, git.ignoreCC)
}

func gitParseCommit(output, user, domain []byte, ignoreCC map[string]bool) (*Commit, error) {
	lines := bytes.Split(output, []byte{'\n'})
	if len(lines) < 8 || len(lines[0]) != 40 {
		return nil, fmt.Errorf("unexpected git log output: %q", output)
	}
	const dateFormat = "Mon Jan 2 15:04:05 2006 -0700"
	date, err := time.Parse(dateFormat, string(lines[4]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse date in git log output: %v\n%q", err, output)
	}
	commitDate, err := time.Parse(dateFormat, string(lines[6]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse date in git log output: %v\n%q", err, output)
	}
	recipients := make(map[string]bool)
	recipients[strings.ToLower(string(lines[2]))] = true
	var tags []string
	// Use summary line + all description lines.
	for _, line := range append([][]byte{lines[1]}, lines[7:]...) {
		if user != nil {
			userPos := bytes.Index(line, user)
			if userPos != -1 {
				domainPos := bytes.Index(line[userPos+len(user)+1:], domain)
				if domainPos != -1 {
					startPos := userPos + len(user)
					endPos := userPos + len(user) + domainPos + 1
					tag := string(line[startPos:endPos])
					present := false
					for _, tag1 := range tags {
						if tag1 == tag {
							present = true
							break
						}
					}
					if !present {
						tags = append(tags, tag)
					}
				}
			}
		}
		for _, re := range ccRes {
			matches := re.FindSubmatchIndex(line)
			if matches == nil {
				continue
			}
			addr, err := mail.ParseAddress(string(line[matches[2]:matches[3]]))
			if err != nil {
				break
			}
			email := strings.ToLower(addr.Address)
			if ignoreCC[email] {
				continue
			}
			recipients[email] = true
			break
		}
	}
	sortedRecipients := make(Recipients, 0, len(recipients))
	for addr := range recipients {
		sortedRecipients = append(sortedRecipients, RecipientInfo{mail.Address{Address: addr}, To})
	}
	sort.Sort(sortedRecipients)
	parents := strings.Split(string(lines[5]), " ")
	com := &Commit{
		Hash:       string(lines[0]),
		Title:      string(lines[1]),
		Author:     string(lines[2]),
		AuthorName: string(lines[3]),
		Parents:    parents,
		Recipients: sortedRecipients,
		Tags:       tags,
		Date:       date,
		CommitDate: commitDate,
	}
	return com, nil
}

func (git *git) GetCommitByTitle(title string) (*Commit, error) {
	commits, _, err := git.GetCommitsByTitles([]string{title})
	if err != nil || len(commits) == 0 {
		return nil, err
	}
	return commits[0], nil
}

const (
	fetchCommitsMaxAgeInYears = 5
)

func (git *git) GetCommitsByTitles(titles []string) ([]*Commit, []string, error) {
	var greps []string
	m := make(map[string]string)
	for _, title := range titles {
		canonical := CanonicalizeCommit(title)
		greps = append(greps, canonical)
		m[canonical] = title
	}
	since := time.Now().Add(-time.Hour * 24 * 365 * fetchCommitsMaxAgeInYears).Format("01-02-2006")
	commits, err := git.fetchCommits(since, "HEAD", "", "", greps, true)
	if err != nil {
		return nil, nil, err
	}
	var results []*Commit
	for _, com := range commits {
		canonical := CanonicalizeCommit(com.Title)
		if orig := m[canonical]; orig != "" {
			delete(m, canonical)
			results = append(results, com)
			com.Title = orig
		}
	}
	var missing []string
	for _, orig := range m {
		missing = append(missing, orig)
	}
	return results, missing, nil
}

func (git *git) ListRecentCommits(baseCommit string) ([]string, error) {
	// On upstream kernel this produces ~11MB of output.
	// Somewhat inefficient to collect whole output in a slice
	// and then convert to string, but should be bearable.
	output, err := git.git("log", "--pretty=format:%s", "-n", "200000", baseCommit)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(output), "\n"), nil
}

func (git *git) ExtractFixTagsFromCommits(baseCommit, email string) ([]*Commit, error) {
	user, domain, err := splitEmail(email)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email %q: %v", email, err)
	}
	grep := user + "+.*" + domain
	since := time.Now().Add(-time.Hour * 24 * 365 * fetchCommitsMaxAgeInYears).Format("01-02-2006")
	return git.fetchCommits(since, baseCommit, user, domain, []string{grep}, false)
}

func (git *git) fetchCommits(since, base, user, domain string, greps []string, fixedStrings bool) ([]*Commit, error) {
	const commitSeparator = "---===syzkaller-commit-separator===---"
	args := []string{"log", "--since", since, "--format=%H%n%s%n%ae%n%an%n%ad%n%P%n%cd%n%b%n" + commitSeparator}
	if fixedStrings {
		args = append(args, "--fixed-strings")
	}
	for _, grep := range greps {
		args = append(args, "--grep", grep)
	}
	args = append(args, base)
	cmd := exec.Command("git", args...)
	cmd.Dir = git.dir
	cmd.Env = filterEnv()
	if git.sandbox {
		if err := osutil.Sandbox(cmd, true, false); err != nil {
			return nil, err
		}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	var (
		s           = bufio.NewScanner(stdout)
		buf         = new(bytes.Buffer)
		separator   = []byte(commitSeparator)
		commits     []*Commit
		userBytes   []byte
		domainBytes []byte
	)
	if user != "" {
		userBytes = []byte(user + "+")
		domainBytes = []byte(domain)
	}
	for s.Scan() {
		ln := s.Bytes()
		if !bytes.Equal(ln, separator) {
			buf.Write(ln)
			buf.WriteByte('\n')
			continue
		}
		com, err := gitParseCommit(buf.Bytes(), userBytes, domainBytes, git.ignoreCC)
		if err != nil {
			return nil, err
		}
		if user == "" || len(com.Tags) != 0 {
			commits = append(commits, com)
		}
		buf.Reset()
	}
	return commits, s.Err()
}

func (git *git) git(args ...string) ([]byte, error) {
	cmd := osutil.Command("git", args...)
	cmd.Dir = git.dir
	cmd.Env = filterEnv()
	if git.sandbox {
		if err := osutil.Sandbox(cmd, true, false); err != nil {
			return nil, err
		}
	}
	//fmt.Printf("running command: %v\n", cmd)
	//fmt.Printf("Params: %v %v %v\n", cmd.Path, cmd.Dir, cmd.Args)

	return osutil.Run(time.Hour, cmd)
}

func splitEmail(email string) (user, domain string, err error) {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", "", err
	}
	at := strings.IndexByte(addr.Address, '@')
	if at == -1 {
		return "", "", fmt.Errorf("no @ in email address")
	}
	user = addr.Address[:at]
	domain = addr.Address[at:]
	if plus := strings.IndexByte(user, '+'); plus != -1 {
		user = user[:plus]
	}
	return
}

func (git *git) Bisect(bad, good string, dt debugtracer.DebugTracer, pred func() (BisectResult,
	error)) ([]*Commit, error) {
	git.reset()
	firstBad, err := git.getCommit(bad)
	if err != nil {
		return nil, err
	}
	output, err := git.git("bisect", "start", bad, good)
	if err != nil {
		return nil, err
	}
	defer git.reset()
	dt.Log("# git bisect start %v %v\n%s", bad, good, output)
	current, err := git.HeadCommit()
	if err != nil {
		return nil, err
	}
	var bisectTerms = [...]string{
		BisectBad:  "bad",
		BisectGood: "good",
		BisectSkip: "skip",
	}
	for {
		res, err := pred()
		// Linux EnvForCommit may cherry-pick some fixes, reset these before the next step.
		git.git("reset", "--hard")
		if err != nil {
			return nil, err
		}
		if res == BisectBad {
			firstBad = current
		}
		output, err = git.git("bisect", bisectTerms[res])
		dt.Log("# git bisect %v %v\n%s", bisectTerms[res], current.Hash, output)
		if err != nil {
			if bytes.Contains(output, []byte("There are only 'skip'ped commits left to test")) {
				return git.bisectInconclusive(output)
			}
			return nil, err
		}
		next, err := git.HeadCommit()
		if err != nil {
			return nil, err
		}
		if current.Hash == next.Hash {
			return []*Commit{firstBad}, nil
		}
		current = next
	}
}

func (git *git) bisectInconclusive(output []byte) ([]*Commit, error) {
	// For inconclusive bisection git prints the following message:
	//
	//	There are only 'skip'ped commits left to test.
	//	The first bad commit could be any of:
	//	1f43f400a2cbb02f3d34de8fe30075c070254816
	//	4d96e13ee9cd1f7f801e8c7f4b12f09d1da4a5d8
	//	5cd856a5ef9aa189df757c322be34ad735a5b17f
	//	We cannot bisect more!
	//
	// For conclusive bisection:
	//
	//	7c3850adbcccc2c6c9e7ab23a7dcbc4926ee5b96 is the first bad commit
	var commits []*Commit
	for _, hash := range regexp.MustCompile("[a-f0-9]{40}").FindAll(output, -1) {
		com, err := git.getCommit(string(hash))
		if err != nil {
			return nil, err
		}
		commits = append(commits, com)
	}
	return commits, nil
}

func (git *git) ReleaseTag(commit string) (string, error) {
	tags, err := git.previousReleaseTags(commit, true, true, true)
	if err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no release tags found for commit %v", commit)
	}
	return tags[0], nil
}

func (git *git) previousReleaseTags(commit string, self, onlyTop, includeRC bool) ([]string, error) {
	var tags []string
	if self {
		output, err := git.git("tag", "--list", "--points-at", commit, "--merged", commit, "v*.*")
		if err != nil {
			return nil, err
		}
		tags = gitParseReleaseTags(output, includeRC)
		if onlyTop && len(tags) != 0 {
			return tags, nil
		}
	}
	output, err := git.git("tag", "--no-contains", commit, "--merged", commit, "v*.*")
	if err != nil {
		return nil, err
	}
	tags1 := gitParseReleaseTags(output, includeRC)
	tags = append(tags, tags1...)
	if len(tags) == 0 {
		return nil, fmt.Errorf("no release tags found for commit %v", commit)
	}
	return tags, nil
}

func (git *git) IsRelease(commit string) (bool, error) {
	tags1, err := git.previousReleaseTags(commit, true, false, false)
	if err != nil {
		return false, err
	}
	tags2, err := git.previousReleaseTags(commit, false, false, false)
	if err != nil {
		return false, err
	}
	return len(tags1) != len(tags2), nil
}
