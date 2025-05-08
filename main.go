package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/go-git/go-git/v5"
	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/golang-jwt/jwt/v5"
)

const (
	GitHubOwner          = "gregkroonorg"
	GitHubRepo           = "terraform-module-upgrade-demo"
	GitHubAppID          = "1188634"  // e.g. "123456"
	GitHubInstallationID = "63155536" // e.g. "7890123"
	GroupBranchName      = "bot-terraform-upgrades"
	PrivateKeyPath       = "/Users/gregkroon/Downloads/harness-integration-app.2025-03-22.private-key.pem" // .pem file from GitHub App
)

type TerraformModule struct {
	Path       string
	Source     string
	Version    string
	NewVersion string
}

func main() {
	githubToken := getGitHubToken()
	repoPath := cloneRepo(githubToken)
	defer os.RemoveAll(repoPath)

	modules := detectModules(repoPath)
	if len(modules) == 0 {
		log.Println("No Terraform modules detected.")
		return
	}

	var majorUpgrades []TerraformModule
	var batchUpgrades []TerraformModule

	for _, mod := range modules {
		latestVersion, err := fetchLatestGitHubRelease(mod.Source, githubToken)
		if err != nil {
			log.Printf("❌ Failed to fetch latest version for %s: %v", mod.Source, err)
			continue
		}
		if shouldUpgrade(mod.Version, latestVersion) {
			mod.NewVersion = latestVersion
			if isMajorUpgrade(mod.Version, latestVersion) {
				majorUpgrades = append(majorUpgrades, mod)
			} else {
				batchUpgrades = append(batchUpgrades, mod)
			}
		}
	}

	if len(batchUpgrades) == 0 && len(majorUpgrades) == 0 {
		log.Println("No upgrades needed.")
		return
	}

	if len(batchUpgrades) > 0 {
		applyModuleUpdates(repoPath, batchUpgrades)
		createPR(repoPath, batchUpgrades, GroupBranchName, githubToken)
		if pr := getOpenPRNumber(GroupBranchName, githubToken); pr > 0 {
			monitorAndMergePR(pr, GroupBranchName, githubToken)
		}
	}

	for _, mod := range majorUpgrades {
		branch := fmt.Sprintf("bot-upgrade-%s", strings.ReplaceAll(filepath.Base(mod.Path), ".", "-"))
		repoPath := cloneRepo(githubToken)
		defer os.RemoveAll(repoPath)

		applyModuleUpdates(repoPath, []TerraformModule{mod})
		createPR(repoPath, []TerraformModule{mod}, branch, githubToken)
		if pr := getOpenPRNumber(branch, githubToken); pr > 0 {
			monitorAndMergePR(pr, branch, githubToken)
		}
	}
}

// -------------------- GITHUB APP AUTH --------------------

func getGitHubToken() string {
	jwt := generateJWT()

	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", GitHubInstallationID)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("❌ Failed to get installation token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("❌ GitHub API error: %s", body)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("❌ Failed to parse token JSON: %v", err)
	}

	log.Println("✅ GitHub Installation Token retrieved successfully:")
	log.Printf("🔑 Token: %s", result.Token)
	log.Printf("⏳ Expires at: %s\n", result.ExpiresAt.UTC().Format(time.RFC3339))
	log.Println("⚠️  Reminder: DO NOT use the JWT for API requests — use this installation token above.")

	return result.Token
}

func generateJWT() string {
	privateKey := loadPrivateKey()
	now := time.Now()

	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(time.Minute * 9).Unix(),
		"iss": GitHubAppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("❌ Failed to sign JWT: %v", err)
	}

	log.Printf("🔐 Generated JWT:\n\n%s\n", signedToken) // <<<<<<<< ADD THIS LINE
	return signedToken
}

func loadPrivateKey() *rsa.PrivateKey {
	keyBytes, err := os.ReadFile(PrivateKeyPath)
	if err != nil {
		log.Fatalf("❌ Failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		log.Fatalf("❌ Failed to parse PEM block")
	}

	parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("❌ Failed to parse private key: %v", err)
	}
	return parsedKey
}

// -------------------- REMAINDER --------------------

func shouldUpgrade(current, latest string) bool {
	currentV, err1 := semver.NewVersion(strings.TrimPrefix(current, "v"))
	latestV, err2 := semver.NewVersion(strings.TrimPrefix(latest, "v"))
	return err1 == nil && err2 == nil && latestV.GreaterThan(currentV)
}

func isMajorUpgrade(current, latest string) bool {
	curr, _ := semver.NewVersion(strings.TrimPrefix(current, "v"))
	newV, _ := semver.NewVersion(strings.TrimPrefix(latest, "v"))
	return curr.Major() < newV.Major()
}

func applyModuleUpdates(repoPath string, modules []TerraformModule) {
	for _, mod := range modules {
		content, _ := os.ReadFile(mod.Path)
		updated := strings.ReplaceAll(string(content), "ref="+mod.Version, "ref="+mod.NewVersion)
		os.WriteFile(mod.Path, []byte(updated), 0644)
		exec.Command("terraform", "fmt", mod.Path).Run()
		log.Printf("✅ Updated %s → %s", mod.Path, mod.NewVersion)
	}
}

func createPR(repoPath string, mods []TerraformModule, branch, token string) {
	runGit(repoPath, "checkout", "-b", branch)
	runGit(repoPath, "add", ".")
	runGit(repoPath, "commit", "-m", "chore: upgrade Terraform modules")
	runGit(repoPath, "push", "--force", "--set-upstream", "origin", branch)

	title := buildPRTitle(mods)
	body := "**This PR updates Terraform module versions.**"

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", GitHubOwner, GitHubRepo)
	payload := map[string]string{"title": title, "head": branch, "base": "main", "body": body}

	jsonBody, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("❌ PR request failed: %v", err)
	}
	defer resp.Body.Close()
	log.Println("✅ Pull request created!")
}

func buildPRTitle(mods []TerraformModule) string {
	if len(mods) == 1 {
		src := strings.TrimPrefix(mods[0].Source, "git::")
		src = strings.TrimPrefix(src, "https://github.com/")
		src = strings.Split(src, "?")[0]
		return fmt.Sprintf("Update Terraform %s to %s", src, mods[0].NewVersion)
	}
	return fmt.Sprintf("Update %d Terraform modules", len(mods))
}

func getOpenPRNumber(branch, token string) int {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", GitHubOwner, GitHubRepo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "token "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("❌ Failed to get PRs: %v", err)
		return -1
	}
	defer resp.Body.Close()

	var prs []struct {
		Number int `json:"number"`
		Head   struct {
			Ref string `json:"ref"`
		} `json:"head"`
	}
	json.NewDecoder(resp.Body).Decode(&prs)

	for _, pr := range prs {
		if pr.Head.Ref == branch {
			return pr.Number
		}
	}
	return -1
}

func monitorAndMergePR(prNumber int, branch, token string) {
	// Step 1: Get PR SHA
	prURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", GitHubOwner, GitHubRepo, prNumber)
	req, _ := http.NewRequest("GET", prURL, nil)
	req.Header.Set("Authorization", "token "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("❌ Failed to get PR details: %v", err)
	}
	defer resp.Body.Close()

	var pr struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		log.Fatalf("❌ Failed to decode PR details: %v", err)
	}
	sha := pr.Head.SHA

	statusURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s/status", GitHubOwner, GitHubRepo, sha)
	log.Printf("🔍 Monitoring commit status for SHA: %s", sha)
	log.Printf("🔗 Status URL: %s", statusURL)

	for {
		req, _ := http.NewRequest("GET", statusURL, nil)
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("❌ Failed to fetch commit status: %v", err)
		}
		defer resp.Body.Close()

		var result struct {
			State    string `json:"state"` // e.g., success, failure, pending
			Statuses []struct {
				Context string `json:"context"`
				State   string `json:"state"`
				URL     string `json:"target_url"`
			} `json:"statuses"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			log.Fatalf("❌ Failed to decode commit status: %v", err)
		}

		log.Printf("🔍 Overall state: %s", result.State)
		for _, s := range result.Statuses {
			log.Printf("  - [%s] status=%s", s.Context, s.State)
		}

		switch result.State {
		case "success":
			log.Println("✅ All status checks passed. Merging PR...")
			mergePR(prNumber, branch, token)
			return
		case "failure", "error":
			log.Fatalf("❌ Status checks failed for PR #%d. Aborting.", prNumber)
		case "pending":
			log.Println("⏳ Status checks still pending. Waiting...")
			time.Sleep(10 * time.Second)
		default:
			log.Printf("⚠️ Unknown state '%s'. Retrying...", result.State)
			time.Sleep(10 * time.Second)
		}
	}
}

func mergePR(prNumber int, branch, token string) {
	mergeURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/merge", GitHubOwner, GitHubRepo, prNumber)
	body := map[string]string{"commit_title": "auto-merge passed"}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("PUT", mergeURL, bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("❌ Merge failed: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("🎉 PR #%d merged successfully!", prNumber)

	// Delete branch after merge
	delURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/heads/%s", GitHubOwner, GitHubRepo, branch)
	req, _ = http.NewRequest("DELETE", delURL, nil)
	req.Header.Set("Authorization", "token "+token)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()

	log.Printf("🧹 Deleted branch: %s", branch)
}

func cloneRepo(token string) string {

	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", GitHubOwner, GitHubRepo)
	repoPath := filepath.Join(os.TempDir(), GitHubRepo)
	os.RemoveAll(repoPath)

	_, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		URL: repoURL,
		Auth: &gitHttp.BasicAuth{
			Username: "x-access-token", // required for GitHub App
			Password: token,
		},
		Progress: os.Stdout,
	})

	if err != nil {
		log.Fatalf("❌ Clone failed: %v", err)
	}
	return repoPath
}

func runGit(repoPath string, args ...string) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("❌ Git failed: %v", err)
	}
}

func detectModules(repoPath string) []TerraformModule {
	var modules []TerraformModule
	_ = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || !strings.HasSuffix(path, ".tf") {
			return nil
		}
		content, _ := os.ReadFile(path)
		re := regexp.MustCompile(`(?m)^\s*source\s*=\s*"([^"]+)"`)
		ref := regexp.MustCompile(`ref=([^"&]+)`)

		for _, match := range re.FindAllStringSubmatch(string(content), -1) {
			if len(match) == 2 {
				source := match[1]
				if v := ref.FindStringSubmatch(source); len(v) == 2 {
					modules = append(modules, TerraformModule{Path: path, Source: source, Version: v[1]})
				}
			}
		}
		return nil
	})
	return modules
}

func fetchLatestGitHubRelease(source, token string) (string, error) {
	src := strings.TrimPrefix(source, "git::")
	src = strings.Split(src, "?")[0]

	re := regexp.MustCompile(`github\.com/([^/]+)/([^/]+)\.git`)
	matches := re.FindStringSubmatch(src)
	if len(matches) < 3 {
		return "", fmt.Errorf("invalid GitHub module source: %s", source)
	}
	owner, repo := matches[1], matches[2]

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/tags", owner, repo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch tags: %v", err)
	}
	defer resp.Body.Close()

	var tags []struct {
		Name string `json:"name"`
	}
	json.NewDecoder(resp.Body).Decode(&tags)
	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found for %s", source)
	}
	return tags[0].Name, nil
}
