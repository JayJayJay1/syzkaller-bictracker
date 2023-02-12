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
	availablePatchesInOrder := [16]string{"a54df7622717a40ddec95fd98086aff8ba7839a6", "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78", "2bb2b7b57f81255c13f4395ea911d6bdc70c9fe2", "9df918698408fd914493aba0b7858fef50eba63a", "8d470a45d1a65e6a308aeee5da7f5b37d3303c04", "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c", "c985aafb60e972c0a6b8d0bd65e03af5890b748a", "b287a25a7148a89d977c819c1f7d6584f875b682", "a3b5c1065f3fb934a87dd07d23def99916023d6f", "7a46ec0e2f4850407de5e1d19a44edee6efa58ec", "b17b01533b719e9949e437abf66436a875739b40", "2553b67a1fbe7bf202e4e8070ab0b00d3d3a06a2", "8d91f8b15361dfb438ab6eb3b319e2ded43458ff", "7bbee5ca3896f69f09c68be549cb8997abe6bca6", "7625b3a0007decf2b135cb47ca67abc78a7b1bc1", "5375b708f2547f70cd2bee2fd8663ab7035f9551"}
	patchesApplicableFor := map[string]string{
		"51094a24b85e29138b7fa82ef1e1b4fe19c90046": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"7535b832c6399b5ebfc5b53af5c51dd915ee2538": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"48ea09cddae0b794cde2070f106ef676703dbcd3": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"8b05aa26336113c4cea25f1c333ee8cd4fc212a6": "a54df7622717a40ddec95fd98086aff8ba7839a6",
		"9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"79cc1ba7badf9e7a12af99695a557e9ce27ee967": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"9360d035a579d95d1e76c471061b9065b18a0eb1": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"5d5dd3e4a86a64cc69fa0fdd32f769b1d97a9a83": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"0a64ce6e5442bbd96cbe9057d9ba1edab244f25b": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"665fe72a7d4f0ad17923e0a5ff2e6cc64d57c970": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"2852ca7fba9f77b204f0fe953b31fadd0057c936": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"51889d225ce2ce118d8413eb4282045add81a689": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"07a22b61946f0b80065b0ddcc703b715f84355f5": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"20fb0c8272bbb102d15bdd11aa64f828619dd7cc": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"38335cc5ffafa111210ad6bbe5a63a87db38ee68": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"b87f02307d3cfbda768520f0687c51ca77e14fc3": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"44d35720c9a660074b77ab9de37abf2c01c5b44f": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"537e62c865dcb9b91d07ed83f8615b71fa0b51bb": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"595b893e2087de306d0781795fb8ec47873596a6": "9fc9e278a5c0b708eeffaf47d6eb0c82aa74ed78",
		"2bb2b7b57f81255c13f4395ea911d6bdc70c9fe2": "2bb2b7b57f81255c13f4395ea911d6bdc70c9fe2",
		"9df918698408fd914493aba0b7858fef50eba63a": "9df918698408fd914493aba0b7858fef50eba63a",
		"f953f140f318a641c443b0b8c618155ed90a7a10": "9df918698408fd914493aba0b7858fef50eba63a",
		"8d470a45d1a65e6a308aeee5da7f5b37d3303c04": "8d470a45d1a65e6a308aeee5da7f5b37d3303c04",
		"1a2383e8b84c0451fd9b1eec3b9aab16f30b597c": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"e83a4472bf9f556d01984048e398e64246c4dd6f": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"23b36fec7e14f8cf1c17e832e53dd4761e0dfe83": "1a2383e8b84c0451fd9b1eec3b9aab16f30b597c",
		"c985aafb60e972c0a6b8d0bd65e03af5890b748a": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"93d102f094be9beab28e5afb656c188b16a3793b": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"f39650de687e35766572ac89dbcd16a5911e2f0a": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"2f31ad64a9cce8b2409d2d4563482adfb8664082": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"3f388f28639fd19d5bf6df7a882c94ccfbf49c2b": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"63037f74725ddd8a767ed2ad0369e60a3bf1f2ce": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"79076e1241bb3bf02d0aac7d39120d8161fe07b1": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"5916d5f9b3347344a3d96ba6b54cf8e290eba96a": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"60c958d8df9cfc40b745d6cd583cfbfa7525ead6": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"db38d5c106dfdd7cb7207c83267d82fdf4950b61": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"2f30b36943adca070f2e1551f701bd524ed1ae5a": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"20bb759a66be52cf4a9ddd17fddaf509e11490cd": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"2da1ead4d5f7fa5f61e5805655de1e245d03a763": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"d38aba49a9f72b862f1220739ca837c886fdc319": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"f2f84b05e02b7710a201f0017b3272ad7ef703d1": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"ee8711336c51708382627ebcaee5f2122b77dfef": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"7d92bda271ddcbb2d1be2f82733dcb9bf8378010": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"570432470275c3da15b85362bc1461945b9c1919": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"53b9537509654a6267c3f56b4d2e7409b9089686": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"457c89965399115e5cd8bf38f9c597293405703d": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"de6da1e8bcf0dd2058b950b127491821207679dc": "c985aafb60e972c0a6b8d0bd65e03af5890b748a",
		"b287a25a7148a89d977c819c1f7d6584f875b682": "b287a25a7148a89d977c819c1f7d6584f875b682",
		"c39ea0b9dd24bf1bf2baa5cdbfa1905f3065347b": "b287a25a7148a89d977c819c1f7d6584f875b682",
		"98587c2d894c34c9af5cd84ca169e1cd493aa692": "b287a25a7148a89d977c819c1f7d6584f875b682",
		"4169680e9f7cdbf893f8885611b3235aeda94224": "b287a25a7148a89d977c819c1f7d6584f875b682",
		"81c9d43f94870be66146739c6e61df40dc17bb64": "b287a25a7148a89d977c819c1f7d6584f875b682",
		"d999bd9392dea7c1a9ac43b8680b22c4425ae4c7": "b287a25a7148a89d977c819c1f7d6584f875b682",
		"a3b5c1065f3fb934a87dd07d23def99916023d6f": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"c7c3f05e341a9a2bd1a92993d4f996cfd6e7348e": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"b49dec1cf8ff1e0b204dd2c30b95a92d75591146": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"95c4fb78fb23081472465ca20d5d31c4b780ed82": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"050e9baa9dc9fbd9ce2b27f0056990fc9e0a08a0": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"bc4f2f5469ac2a52affadc4c00c1276d76151a39": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"9c4560e5bbd8c839c8986f79ef536aa07bd77ec7": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"47d4b263a2f7324fb3cb641ca00b2725dd12dea0": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"2a56bb596b2c1fb612f9988afda9655c8c872a6e": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"4c281074d2e7beb8179d81c3d2c2a53ae47dfa1c": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"54dce3c35bbbeaab8de4b82d3ef3a2f011229662": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"0862ca422b79cb5aa70823ee0f07f6b468f86070": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"5ad751053704df3f00d2bb2dc9345c697c212150": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"4efb442cc12eb66535b7c7ed06005fd7889c1d77": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"a7bed27af194aa3f67915688039d93188ed95e2a": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"2a8358d8a339540f00ec596526690e8eeca931a3": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"aaf5dcfb223617ac2d16113e4b500199c65689de": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"b1fca27d384e8418aac84b39f6f5179aecc1b64f": "a3b5c1065f3fb934a87dd07d23def99916023d6f",
		"7a46ec0e2f4850407de5e1d19a44edee6efa58ec": "7a46ec0e2f4850407de5e1d19a44edee6efa58ec",
		"b17b01533b719e9949e437abf66436a875739b40": "b17b01533b719e9949e437abf66436a875739b40",
		"7db60d05e5ccc0a473fa2275f90f2fca0002ab21": "b17b01533b719e9949e437abf66436a875739b40",
		"7d91de74436a69c2b78a7a72f1e7f97f8b4396fa": "b17b01533b719e9949e437abf66436a875739b40",
		"f92bac3b141b8233e34ddf32d227e12bfba07b48": "b17b01533b719e9949e437abf66436a875739b40",
		"ff7a28a074ccbea999dadbb58c46212cf90984c6": "b17b01533b719e9949e437abf66436a875739b40",
		"5eb7c0d04f04a667c049fe090a95494a8de2955c": "b17b01533b719e9949e437abf66436a875739b40",
		"7fd8329ba502ef76dd91db561c7aed696b2c7720": "b17b01533b719e9949e437abf66436a875739b40",
		"0ee59413c967c35a6dd2dbdab605b4cd42025ee5": "b17b01533b719e9949e437abf66436a875739b40",
		"b26e27ddfd2a986dc53e259aba572f3aac182eb8": "b17b01533b719e9949e437abf66436a875739b40",
		"cf9b1106c81c45cde02208fca49d3f3e4ab6ee74": "b17b01533b719e9949e437abf66436a875739b40",
		"ebc41f20d77f6ad91f1f2d2af5147dc9bb6b5eea": "b17b01533b719e9949e437abf66436a875739b40",
		"2553b67a1fbe7bf202e4e8070ab0b00d3d3a06a2": "2553b67a1fbe7bf202e4e8070ab0b00d3d3a06a2",
		"8d91f8b15361dfb438ab6eb3b319e2ded43458ff": "8d91f8b15361dfb438ab6eb3b319e2ded43458ff",
		"7bbee5ca3896f69f09c68be549cb8997abe6bca6": "7bbee5ca3896f69f09c68be549cb8997abe6bca6",
		"58c5661f2144c089bbc2e5d87c9ec1dc1d2964fe": "7bbee5ca3896f69f09c68be549cb8997abe6bca6",
		"1717f2096b543cede7a380c858c765c41936bc35": "7bbee5ca3896f69f09c68be549cb8997abe6bca6",
		"7625b3a0007decf2b135cb47ca67abc78a7b1bc1": "7625b3a0007decf2b135cb47ca67abc78a7b1bc1",
		"08d78658f393fefaa2e6507ea052c6f8ef4002a2": "7625b3a0007decf2b135cb47ca67abc78a7b1bc1",
		"5375b708f2547f70cd2bee2fd8663ab7035f9551": "5375b708f2547f70cd2bee2fd8663ab7035f9551",
		"f45d85ff1f3f13d5b67fecb291edc6a771db0c53": "5375b708f2547f70cd2bee2fd8663ab7035f9551",
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
