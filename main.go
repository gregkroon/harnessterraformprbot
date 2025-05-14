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
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/go-git/go-git/v5"
	gitHttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/golang-jwt/jwt/v5"
)

var (
	HarnessAPIKey        = os.Getenv("HARNESS_API_KEY")
	GitHubOwner          = os.Getenv("GITHUB_OWNER")
	GitHubAppID          = os.Getenv("GITHUB_APP_ID")
	GitHubInstallationID = os.Getenv("GITHUB_INSTALLATION_ID")
	GroupBranchName      = os.Getenv("GROUP_BRANCH_NAME")
	
)

var GitHubRepos = deduplicate(strings.Split(os.Getenv("GITHUB_REPOS"), ","))
var AutoMergeEnabled = strings.ToLower(os.Getenv("AUTO_MERGE")) == "true"

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

type PRResult struct {
	Repo   string
	PR     int
	Status string // success, failed, skipped
}

func main() {
	required := []string{
		"HARNESS_API_KEY", "GITHUB_OWNER", "GITHUB_APP_ID", "GITHUB_INSTALLATION_ID", "GROUP_BRANCH_NAME", "GITHUB_REPOS",
	}
	for _, env := range required {
		if os.Getenv(env) == "" {
			log.Fatalf("❌ Missing required environment variable: %s", env)
		}
	}

	if len(GitHubRepos) == 0 {
		log.Fatal("❌ GITHUB_REPOS is not set or contains only invalid/empty entries.")
	}

	githubToken := getGitHubToken()
	harnessAPIKey := HarnessAPIKey

	var wg sync.WaitGroup
	maxConcurrent := 4
	semaphore := make(chan struct{}, maxConcurrent)

	var resultsMu sync.Mutex
	var results []PRResult

	for _, repo := range GitHubRepos {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(repo string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			repoResults := processRepo(repo, githubToken, harnessAPIKey)

			resultsMu.Lock()
			results = append(results, repoResults...)
			resultsMu.Unlock()
		}(repo)
	}

	wg.Wait()

	fmt.Println("\n📊 Upgrade Summary:")
	if len(results) == 0 {
		fmt.Println("No upgrades were performed.")
		return
	}

	for _, r := range results {
		status := strings.ToUpper(r.Status)
		switch status {
		case "SUCCESS":
			fmt.Printf("✅ %-40s PR #%d → %s\n", r.Repo, r.PR, status)
		case "FAILED":
			fmt.Printf("❌ %-40s PR #%d → %s\n", r.Repo, r.PR, status)
		case "TIMEOUT":
			fmt.Printf("⏰ %-40s PR #%d → %s\n", r.Repo, r.PR, status)
		default:
			fmt.Printf("⚠️ %-40s PR #%d → %s\n", r.Repo, r.PR, status)
		}
	}
}

func processRepo(repo, githubToken, harnessAPIKey string) []PRResult {
	log.Printf("🚀 Processing repository: %s", repo)
	repoPath := cloneRepo(githubToken, repo)
	defer os.RemoveAll(repoPath)

	modules := detectModules(repoPath)
	if len(modules) == 0 {
		log.Printf("📭 No Terraform modules detected in %s", repo)
		return nil
	}

	var majorUpgrades, batchUpgrades []TerraformModule
	var results []PRResult

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
		branch := fmt.Sprintf("bot-upgrades-%s", strings.ReplaceAll(repo, ".", "-"))
		applyModuleUpdates(repoPath, batchUpgrades)
		createPR(repo, repoPath, batchUpgrades, branch, githubToken)
		if pr := getOpenPRNumber(repo, branch, githubToken); pr > 0 {
			status := monitorAndMergePR(repo, pr, branch, githubToken)
			results = append(results, PRResult{Repo: repo, PR: pr, Status: status})
		}
	}

	for _, mod := range majorUpgrades {
		branch := fmt.Sprintf("bot-upgrade-%s-%s", strings.ReplaceAll(repo, ".", "-"), strings.ReplaceAll(filepath.Base(mod.Path), ".", "-"))
		repoPath := cloneRepo(githubToken, repo)
		defer os.RemoveAll(repoPath)
		applyModuleUpdates(repoPath, []TerraformModule{mod})
		createPR(repo, repoPath, []TerraformModule{mod}, branch, githubToken)
		if pr := getOpenPRNumber(repo, branch, githubToken); pr > 0 {
			status := monitorAndMergePR(repo, pr, branch, githubToken)
			results = append(results, PRResult{Repo: repo, PR: pr, Status: status})
		}
	}

	if len(results) == 0 {
		log.Printf("✅ No module upgrades needed in %s", repo)
	}
	return results
}

func monitorAndMergePR(repo string, prNumber int, branch, token string) string {
	prURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", GitHubOwner, repo, prNumber)

	req, _ := http.NewRequest("GET", prURL, nil)
	req.Header.Set("Authorization", "token "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("❌ Failed to get PR #%d details for repo %s: %v", prNumber, repo, err)
		return "failed"
	}
	defer resp.Body.Close()

	var pr struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		log.Printf("❌ Failed to decode PR #%d details for repo %s: %v", prNumber, repo, err)
		return "failed"
	}
	sha := pr.Head.SHA

	statusURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s/status", GitHubOwner, repo, sha)
	log.Printf("🔍 Monitoring commit status for PR #%d in repo %s (SHA: %s)", prNumber, repo, sha)

	timeout := time.After(15 * time.Minute)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			log.Printf("⏰ Timeout reached while waiting for status checks on PR #%d in repo %s", prNumber, repo)
			return "timeout"

		case <-ticker.C:
			req, _ := http.NewRequest("GET", statusURL, nil)
			req.Header.Set("Authorization", "token "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("❌ Failed to fetch commit status for PR #%d in repo %s: %v", prNumber, repo, err)
				return "failed"
			}
			defer resp.Body.Close()

			var result struct {
				State string `json:"state"` // success, failure, pending
			}
			json.NewDecoder(resp.Body).Decode(&result)

			switch result.State {
			case "success":
				log.Printf("✅ All checks passed for PR #%d in repo %s.", prNumber, repo)
				if AutoMergeEnabled {
					log.Printf("🔁 Auto-merge is enabled. Merging PR #%d...", prNumber)
					mergePR(repo, prNumber, branch, token)
					return "success"
				}
				log.Printf("🚫 Auto-merge is disabled. Skipping merge for PR #%d.", prNumber)
				return "skipped"

			case "failure", "error":
				log.Printf("❌ Status checks failed for PR #%d in repo %s. Skipping merge.", prNumber, repo)
				return "failed"

			case "pending":
				log.Printf("⏳ Status checks pending for PR #%d in repo %s...", prNumber, repo)

			default:
				log.Printf("⚠️ Unknown status '%s' for PR #%d in repo %s. Retrying...", result.State, prNumber, repo)
			}
		}
	}
}

func mergePR(repo string, prNumber int, branch, token string) {
	mergeURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/merge", GitHubOwner, repo, prNumber)

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
	delURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/refs/heads/%s", GitHubOwner, repo, branch)

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
		if err != nil {
			log.Printf("⚠️ Error reading file %s: %v", path, err)
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(path, ".tf") {
			return nil
		}

		log.Printf("🔍 Scanning file: %s", path)
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			log.Printf("⚠️ Failed to read file %s: %v", path, err)
			return nil
		}

		lines := strings.Split(string(contentBytes), "\n")

		var inModuleBlock bool
		var current TerraformModule

		for _, line := range lines {
			trim := strings.TrimSpace(line)

			if moduleStartRe.MatchString(trim) {
				inModuleBlock = true
				current = TerraformModule{Path: path}
			}

			if inModuleBlock {
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

				if strings.HasPrefix(trim, "version") {
					val := extractValue(trim)
					current.Version = val
				}

				if strings.HasPrefix(trim, "}") {
					if current.Source == "" {
						log.Printf("⚠️ Skipping module in %s: missing source", path)
					} else if current.Version == "" {
						log.Printf("⚠️ Skipping module in %s: missing version", path)
					} else {
						log.Printf("✅ Found module: %s version=%s", current.Source, current.Version)
						modules = append(modules, current)
					}
					inModuleBlock = false
				}
			}
		}

		return nil
	})

	if len(modules) == 0 {
		log.Println("📭 No modules with both source and version found.")
	}

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
	rawKey := os.Getenv("GITHUB_PRIVATE_KEY")
	if rawKey == "" {
		log.Fatal("❌ GITHUB_PRIVATE_KEY environment variable is not set")
	}

	log.Printf("🔍 Raw key (first 50 chars): %.50s", rawKey)

	// Common fixes for escaped or broken format
	rawKey = strings.ReplaceAll(rawKey, `\n`, "\n")
	rawKey = strings.Replace(rawKey, "-----BEGIN RSA PRIVATE KEY----- ", "-----BEGIN RSA PRIVATE KEY-----\n", 1)
	rawKey = strings.Replace(rawKey, " -----END RSA PRIVATE KEY-----", "\n-----END RSA PRIVATE KEY-----", 1)
	rawKey = strings.TrimSpace(rawKey)
	rawKey = strings.Trim(rawKey, "\"")

	block, _ := pem.Decode([]byte(rawKey))
	if block == nil {
		log.Fatal("❌ Failed to parse PEM block from GITHUB_PRIVATE_KEY")
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

func createPR(repo, repoPath string, mods []TerraformModule, _unused string, token string) {
	branch := fmt.Sprintf("bot-upgrades-%s", strings.ReplaceAll(repo, ".", "-"))

	runGit(repoPath, "checkout", "main")
	log.Printf("🧨 Deleting remote branch: %s", branch)
	runGitOptional(repoPath, "push", "origin", "--delete", branch)

	log.Println("⏳ Waiting for GitHub to unlock deleted ref...")
	time.Sleep(4 * time.Second)

	runGit(repoPath, "checkout", "-b", branch)
	runGit(repoPath, "add", ".")

	// ✅ Git author identity from env or fallback
	authorName := os.Getenv("GIT_AUTHOR_NAME")
	if authorName == "" {
		authorName = "Terraform Upgrade Bot"
	}
	authorEmail := os.Getenv("GIT_AUTHOR_EMAIL")
	if authorEmail == "" {
		authorEmail = "bot@harness.io"
	}
	runGit(repoPath, "config", "user.name", authorName)
	runGit(repoPath, "config", "user.email", authorEmail)

	runGit(repoPath, "commit", "-m", "chore: upgrade Terraform modules")

	// ✅ Retry git push up to 5 times with backoff
	maxRetries := 5
	var pushErr error
	for i := 1; i <= maxRetries; i++ {
		log.Printf("📤 Attempt %d to push branch '%s'...", i, branch)
		pushErr = runGitWithErr(repoPath, "push", "--force", "--set-upstream", "origin", branch)
		if pushErr == nil {
			log.Println("✅ Push successful.")
			break
		}
		log.Printf("❌ Push failed (attempt %d): %v", i, pushErr)
		time.Sleep(time.Duration(i*2) * time.Second) // exponential backoff
	}
	if pushErr != nil {
		log.Fatalf("❌ Failed to push branch after %d attempts: %v", maxRetries, pushErr)
	}

	// ✅ Check if a PR already exists
	if pr := getOpenPRNumber(repo, branch, token); pr > 0 {
		log.Printf("⚠️ PR already exists for branch '%s' in repo '%s', skipping PR creation.", branch, repo)
		return
	}

	title := buildPRTitle(mods)
	body := "**This PR updates Terraform module versions.**"

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", GitHubOwner, repo)

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

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ Failed to create PR: %s", string(body))
	}

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

func cloneRepo(token, repo string) string {
	repoURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s/%s.git", token, GitHubOwner, repo)
	repoPath, err := os.MkdirTemp("", fmt.Sprintf("repo-%s-*", repo))
	if err != nil {
		log.Fatalf("❌ Failed to create temp dir: %v", err)
	}

	_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
		URL:      repoURL,
		Progress: os.Stdout,
	})
	if err != nil {
		log.Fatalf("❌ Clone failed for %s: %v", repo, err)
	}
	return repoPath
}

func getOpenPRNumber(repo, branch, token string) int {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", GitHubOwner, repo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "token "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("❌ Failed to get PRs for %s: %v", repo, err)
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

func runGit(repoPath string, args ...string) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("❌ Git failed: %v", err)
	}
}

func runGitOptional(repoPath string, args ...string) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run() // we ignore errors on purpose
}

func runGitWithErr(repoPath string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func deduplicate(repos []string) []string {
	seen := make(map[string]struct{})
	var unique []string
	for _, repo := range repos {
		trimmed := strings.TrimSpace(repo)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; !exists {
			seen[trimmed] = struct{}{}
			unique = append(unique, trimmed)
		}
	}
	return unique
}

