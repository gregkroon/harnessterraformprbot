
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
	HarnessAPIKey        = "pat"
	GitHubOwner          = "gregkroonorg"
	GitHubRepo           = "terraform-module-upgrade-demo-harnessrepo"
	GitHubAppID          = "1234"
	GitHubInstallationID = "1234"
	GroupBranchName      = "bot-terraform-upgrades"
	PrivateKeyPath       = "/Users/gregkroon/Downloads/harness-integration-app.2025-03-22.private-key.pem"
)

type TerraformModule struct {
	Path       string
	Source     string
	Version    string
	NewVersion string
	SourceType string
	Org        string
	Project    string
	ModuleName string
	AccountID  string
	System     string
}

func main() {
	githubToken := getGitHubToken()
	harnessAPIKey := HarnessAPIKey
	repoPath := cloneRepo(githubToken)
	defer os.RemoveAll(repoPath)

	modules := detectModules(repoPath)
	if len(modules) == 0 {
		log.Println("No Terraform modules detected.")
		return
	}

	var majorUpgrades, batchUpgrades []TerraformModule

	for _, mod := range modules {
		var latestVersion string
		var err error

		switch mod.SourceType {
		case "github":
			latestVersion, err = fetchLatestGitHubRelease(mod.Source, githubToken)
		case "harness":
			latestVersion, err = fetchLatestHarnessModuleVersion(mod.Org, mod.Project, mod.ModuleName, harnessAPIKey)
		case "harness-account":
			latestVersion, err = fetchLatestHarnessAccountModuleVersion(mod.AccountID, mod.ModuleName, mod.System, harnessAPIKey)
		default:
			log.Printf("⚠️ Unknown source type for module: %s", mod.Source)
			continue
		}

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

	if len(batchUpgrades) == 0 && len(majorUpgrades) == 0 {
		log.Println("✅ No module upgrades needed.")
	}
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

	for {
		req, _ := http.NewRequest("GET", statusURL, nil)
		req.Header.Set("Authorization", "token "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("❌ Failed to fetch commit status: %v", err)
		}
		defer resp.Body.Close()

		var result struct {
			State string `json:"state"` // success, failure, pending
		}
		json.NewDecoder(resp.Body).Decode(&result)

		switch result.State {
		case "success":
			log.Println("✅ All checks passed. Merging PR...")
			mergePR(prNumber, branch, token)
			return
		case "failure", "error":
			log.Fatalf("❌ Status checks failed for PR #%d. Aborting.", prNumber)
		case "pending":
			log.Println("⏳ Status checks pending...")
			time.Sleep(10 * time.Second)
		default:
			log.Printf("⚠️ Unknown status '%s'. Retrying...", result.State)
			time.Sleep(10 * time.Second)
		}
	}
}

func mergePR(prNumber int, branch, token string) {
	mergeURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/merge", GitHubOwner, GitHubRepo, prNumber)
	body := map[string]string{
		"commit_title": fmt.Sprintf("auto-merge PR #%d", prNumber),
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("PUT", mergeURL, bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("❌ Merge failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Failed to merge PR #%d: %s", prNumber, string(body))
	}

	log.Printf("🎉 PR #%d merged successfully!", prNumber)

	// Delete branch
	delURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/heads/%s", GitHubOwner, GitHubRepo, branch)
	req, _ = http.NewRequest("DELETE", delURL, nil)
	req.Header.Set("Authorization", "token "+token)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("⚠️ Failed to delete branch: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("🧹 Deleted branch: %s", branch)
}

func fetchLatestHarnessAccountModuleVersion(accountID, moduleName, systemName, apiKey string) (string, error) {
	url := fmt.Sprintf(
		"https://app.harness.io/iacm/registry/account/%s/%s/%s/versions",
		accountID, moduleName, systemName,
	)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-api-key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch versions: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Harness API error: %s", body)
	}

	var result struct {
		Modules []struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"modules"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	var latest *semver.Version
	for _, mod := range result.Modules {
		for _, v := range mod.Versions {
			sv, err := semver.NewVersion(strings.TrimPrefix(v.Version, "v"))
			if err != nil {
				continue
			}
			if latest == nil || sv.GreaterThan(latest) {
				latest = sv
			}
		}
	}

	if latest == nil {
		return "", fmt.Errorf("no valid versions found")
	}
	return fmt.Sprintf("v%s", latest.String()), nil
}

func fetchLatestGitHubRelease(source, token string) (string, error) {
	src := strings.TrimPrefix(source, "git::")
	src = strings.Split(src, "?")[0]

	if !strings.HasPrefix(src, "https://github.com/") {
		return "", fmt.Errorf("invalid GitHub module source: %s", source)
	}

	parts := strings.Split(strings.TrimPrefix(src, "https://github.com/"), "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid GitHub module path: %s", source)
	}
	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")

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
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("failed to decode GitHub tags: %v", err)
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found for %s", source)
	}

	latest := tags[0].Name
	for _, tag := range tags {
		current, err := semver.NewVersion(strings.TrimPrefix(tag.Name, "v"))
		if err != nil {
			continue
		}
		latestSemver, err := semver.NewVersion(strings.TrimPrefix(latest, "v"))
		if err != nil || current.GreaterThan(latestSemver) {
			latest = tag.Name
		}
	}

	return latest, nil
}

func detectModules(repoPath string) []TerraformModule {
	var modules []TerraformModule
	moduleStartRe := regexp.MustCompile(`^\s*module\s+"[^"]+"\s*{`)

	_ = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || !strings.HasSuffix(path, ".tf") {
			return nil
		}

		contentBytes, _ := os.ReadFile(path)
		lines := strings.Split(string(contentBytes), "\n")

		var inModuleBlock bool
		var current TerraformModule

		for _, line := range lines {
			trim := strings.TrimSpace(line)

			if moduleStartRe.MatchString(line) {
				inModuleBlock = true
				current = TerraformModule{Path: path}
			}

			if inModuleBlock {
				// Extract source
				if strings.HasPrefix(trim, "source") {
					val := extractValue(trim)
					current.Source = val

					switch {
					case strings.HasPrefix(val, "git::"):
						current.SourceType = "github"
					case strings.HasPrefix(val, "harness/"):
						parts := strings.Split(val, "/")
						if len(parts) == 4 {
							current.SourceType = "harness"
							current.Org = parts[1]
							current.Project = parts[2]
							current.ModuleName = parts[3]
						}
					case strings.HasPrefix(val, "app.harness.io/"):
						parts := strings.Split(val, "/")
						if len(parts) == 4 {
							current.SourceType = "harness-account"
							current.AccountID = parts[1]
							current.ModuleName = parts[2]
							current.System = parts[3]
						}
					}
				}

				// Extract version
				if strings.HasPrefix(trim, "version") {
					val := extractValue(trim)
					current.Version = val
				}

				if strings.HasPrefix(trim, "}") {
					if current.Source != "" && current.Version != "" {
						modules = append(modules, current)
					}
					inModuleBlock = false
				}
			}
		}

		return nil
	})

	return modules
}

// extractValue parses `key = "value"` into value
func extractValue(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(parts[1]), `"`)
}

func fetchLatestHarnessModuleVersion(org, project, moduleName, apiKey string) (string, error) {
	url := fmt.Sprintf("https://app.harness.io/gateway/iacm/api/v1/orgs/%s/projects/%s/modules/%s/versions", org, project, moduleName)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-api-key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch Harness versions: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Harness API error: %s", body)
	}

	var result struct {
		Data struct {
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode Harness response: %v", err)
	}

	var latest *semver.Version
	for _, v := range result.Data.Versions {
		sv, err := semver.NewVersion(v.Version)
		if err != nil {
			continue
		}
		if latest == nil || sv.GreaterThan(latest) {
			latest = sv
		}
	}
	if latest == nil {
		return "", fmt.Errorf("no valid semver versions found")
	}
	return latest.String(), nil
}

func applyModuleUpdates(repoPath string, modules []TerraformModule) {
	for _, mod := range modules {
		contentBytes, _ := os.ReadFile(mod.Path)
		content := string(contentBytes)

		// Only update version string inside the correct module block
		lines := strings.Split(content, "\n")
		var output []string
		inBlock := false

		for _, line := range lines {
			trim := strings.TrimSpace(line)

			if strings.HasPrefix(trim, "source") && strings.Contains(line, mod.Source) {
				inBlock = true
			}

			if inBlock && strings.HasPrefix(trim, "version") {
				// Replace the version value
				newLine := regexp.MustCompile(`version\s*=\s*".*"`).
					ReplaceAllString(line, fmt.Sprintf(`version = "%s"`, mod.NewVersion))
				output = append(output, newLine)
			} else {
				output = append(output, line)
			}

			// End block
			if inBlock && strings.HasPrefix(trim, "}") {
				inBlock = false
			}
		}

		newContent := strings.Join(output, "\n")
		os.WriteFile(mod.Path, []byte(newContent), 0644)
		exec.Command("terraform", "fmt", mod.Path).Run()
		log.Printf("✅ Updated %s → %s", mod.ModuleName, mod.NewVersion)
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

	log.Println("✅ GitHub Installation Token retrieved successfully")
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

func cloneRepo(token string) string {
	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", GitHubOwner, GitHubRepo)
	repoPath := filepath.Join(os.TempDir(), GitHubRepo)
	os.RemoveAll(repoPath)

	_, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		URL: repoURL,
		Auth: &gitHttp.BasicAuth{
			Username: "x-access-token",
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
