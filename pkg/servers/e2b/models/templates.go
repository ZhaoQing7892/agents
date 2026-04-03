package models

import "time"

// Template represents an E2B template
type Template struct {
	TemplateID    string     `json:"templateID"`
	Public        bool       `json:"public"`
	Aliases       []string   `json:"aliases"`
	Names         []string   `json:"names"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	LastSpawnedAt *time.Time `json:"lastSpawnedAt"`
	SpawnCount    int64      `json:"spawnCount"`
	Builds        []Build    `json:"builds"`
}

// TemplateInfo represents simplified template information for list response
type TemplateInfo struct {
	TemplateID    string     `json:"templateID"`
	BuildID       string     `json:"buildID"`
	CPUCount      int        `json:"cpuCount"`
	MemoryMB      int        `json:"memoryMB"`
	DiskSizeMB    int        `json:"diskSizeMB"`
	Public        bool       `json:"public"`
	Aliases       []string   `json:"aliases"`
	Names         []string   `json:"names"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	CreatedBy     *TeamUser  `json:"createdBy"`
	LastSpawnedAt *time.Time `json:"lastSpawnedAt"`
	SpawnCount    int64      `json:"spawnCount"`
	BuildCount    int        `json:"buildCount"`
	EnvdVersion   string     `json:"envdVersion"`
	BuildStatus   string     `json:"buildStatus"`
}

// Build represents a build of a template
type Build struct {
	BuildID     string    `json:"buildID"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	CPUCount    int       `json:"cpuCount"`
	MemoryMB    int       `json:"memoryMB"`
	FinishedAt  time.Time `json:"finishedAt"`
	DiskSizeMB  int       `json:"diskSizeMB"`
	EnvdVersion string    `json:"envdVersion"`
}
