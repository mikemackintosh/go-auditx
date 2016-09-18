package bsm

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var EventTypes = ParseEvents(AUDIT_EVENT_FILE)

type EventsDictionary map[uint16]EventDefinition
type EventDefinition struct {
	ID       uint16
	Constant string
	Name     string
	Flag     []string
}

func ParseEvents(eventsFile string) EventsDictionary {
	eventDefinitions, err := ParseEventsFile(AUDIT_EVENT_FILE)
	if err != nil {
		panic(err)
	}
	return eventDefinitions
}

func ParseEventsFile(eventsFile string) (EventsDictionary, error) {
	var ed = EventsDictionary{}

	if _, err := os.Stat(eventsFile); err == nil {
		file, err := os.Open(eventsFile)
		if err != nil {
			return ed, fmt.Errorf("No events file found.")
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// trim the line from all leading whitespace first
			line := strings.TrimLeft(scanner.Text(), " \t")
			// line is not empty, and not starting with '#'
			if len(line) > 0 && !strings.HasPrefix(line, "#") {
				event := strings.SplitN(line, ":", 4)
				if len(event) == 4 {
					eventID, _ := strconv.ParseInt(event[0], 10, 16)
					eid := uint16(eventID)
					definition := EventDefinition{
						ID:       eid,
						Constant: event[1],
						Name:     event[2],
						Flag:     strings.Split(event[3], ","),
					}
					ed[eid] = definition
				}
			}
		}

		// If there was an error running scan, then return
		if err := scanner.Err(); err != nil {
			return ed, fmt.Errorf("Unable to read events file.")
		}
	}

	return ed, nil
}
