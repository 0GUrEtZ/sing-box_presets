package io

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FileInfo представляет информацию о файле
type FileInfo struct {
	Path    string
	Name    string
	Preview string
}

// ListFiles возвращает список файлов в директории
func ListFiles(dir string) ([]FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var files []FileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		info := FileInfo{
			Path: path,
			Name: entry.Name(),
		}

		if preview, err := getFilePreview(path); err == nil {
			info.Preview = preview
		}

		files = append(files, info)
	}

	return files, nil
}

func getFilePreview(path string) (string, error) {
	networks, err := LoadFile(path)
	if err != nil {
		return "", err
	}
	if len(networks) == 0 {
		return "(no networks)", nil
	}
	return fmt.Sprintf("%s ... (%d networks)", networks[0], len(networks)), nil
}

// LoadFile загружает список CIDR из файла (TXT или JSON)
func LoadFile(path string) ([]string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".txt":
		return loadTXT(path)
	case ".json":
		return loadJSON(path)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}
}

// LoadFiles загружает CIDR из нескольких файлов
func LoadFiles(paths []string) ([]string, error) {
	seen := make(map[string]bool)
	var result []string

	for _, path := range paths {
		lines, err := LoadFile(path)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			if !seen[line] {
				seen[line] = true
				result = append(result, line)
			}
		}
	}

	return result, nil
}

var cidrPattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b`)

func normalizeCIDR(s string) string {
	if !strings.Contains(s, "/") {
		return s + "/32"
	}
	return s
}

func loadTXT(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, m := range cidrPattern.FindAllString(line, -1) {
			result = append(result, normalizeCIDR(m))
		}
	}

	return result, scanner.Err()
}

func loadJSON(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	matches := cidrPattern.FindAllString(string(data), -1)

	// Первый проход: собираем IP, у которых явно указан CIDR (есть /)
	withCIDR := make(map[string]bool, len(matches))
	for _, m := range matches {
		if strings.Contains(m, "/") {
			withCIDR[strings.SplitN(m, "/", 2)[0]] = true
		}
	}

	// Второй проход: добавляем, пропуская bare IP если уже есть CIDR для того же адреса
	seen := make(map[string]bool, len(matches))
	var result []string
	for _, m := range matches {
		if !strings.Contains(m, "/") && withCIDR[m] {
			continue // есть более точная запись с маской — пропускаем bare IP
		}
		norm := normalizeCIDR(m)
		if !seen[norm] {
			seen[norm] = true
			result = append(result, norm)
		}
	}
	return result, nil
}

// SaveFile сохраняет CIDR список в файл
func SaveFile(path string, networks []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, network := range networks {
		fmt.Fprintln(writer, network)
	}

	return writer.Flush()
}
