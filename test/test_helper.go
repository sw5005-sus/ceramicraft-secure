package test

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func LoadEnvFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			fmt.Println("Error closing file:", cerr)
		}
	}()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// parse key=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// set environment variable
		err = os.Setenv(key, value)
		if err != nil {
			return err
		}
	}

	return scanner.Err()
}
