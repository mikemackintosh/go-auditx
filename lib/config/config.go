package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var (
	// EnvironmentFile is the environment config file for supplying docker host
	// and AWS credentials to the specific modules
	EnvironmentFile string
)

// ConfigureEnvironment takes a configuration file and loads
// each entry into the process environment for inclusion
func ConfigureEnvironment(configFile string) (bool, error) {
	if _, err := os.Stat(configFile); err == nil {
		file, err := os.Open(configFile)
		if err != nil {
			return true, fmt.Errorf("No configuration file found. Skipping.")
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// trim the line from all leading whitespace first
			line := strings.TrimLeft(scanner.Text(), " \t")
			// line is not empty, and not starting with '#'
			if len(line) > 0 && !strings.HasPrefix(line, "#") {
				data := strings.SplitN(line, "=", 2)
				if len(data) == 2 {
					os.Setenv(data[0], data[1])
				}
			}
		}

		// If there was an error running scan, then return
		if err := scanner.Err(); err != nil {
			return false, fmt.Errorf("Unable to read configuration file.")
		}
	}

	// Looks good, return
	return true, nil
}
