package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"slices"
)

var (
	extractActorId  = regexp.MustCompile(`"actorID":"([^"]+)"`)
	extractEventId  = regexp.MustCompile(`"id":"([^"]+)"`)
	extractHostname = regexp.MustCompile(`"hostname":"([^"]+)"`)
)

type Filters struct {
	EventIds  map[string][]string
	ObjectIds map[string][]string
}

type LabelingTask struct {
	EventId  string   `json:"event_id"`
	Hostname string   `json:"hostname"`
	Labels   []string `json:"labels"`
	ObjectId string   `json:"object_id"`
}

type LogLine struct {
	Action    string `json:"action"`
	ActorId   string `json:"actorID"`
	Hostname  string `json:"hostname"`
	Id        string `json:"id"`
	Object    string `json:"object"`
	ObjectId  string `json:"objectID:`
	Timestamp string `json:"timestamp"`
}

func loadTasks() (tasks []LabelingTask, err error) {
	f, err := os.Open("tasks.json")
	if err != nil {
		return
	}

	data, _ := ioutil.ReadAll(f)
	err = json.Unmarshal(data, &tasks)
	if err != nil {
		return
	}

	return
}

func makeFilters(tasks []LabelingTask) Filters {
	filters := Filters{
		EventIds:  make(map[string][]string),
		ObjectIds: make(map[string][]string),
	}

	for _, task := range tasks {
		if task.EventId == "" {
			continue
		}

		if !slices.Contains(task.Labels, "process") {
			continue
		}

		if _, ok := filters.ObjectIds[task.ObjectId]; !ok {
			filters.ObjectIds[task.ObjectId] = []string{}
		}

		for _, l := range task.Labels {
			if !slices.Contains(filters.ObjectIds[task.ObjectId], l) {
				filters.ObjectIds[task.ObjectId] = append(filters.ObjectIds[task.ObjectId], l)
			}
		}
	}

	for _, task := range tasks {
		if task.EventId == "" {
			continue
		}

		filters.EventIds[task.EventId] = []string{}
		if s, ok := filters.ObjectIds[task.ObjectId]; ok {
			for _, l := range s {
				if !slices.Contains(filters.EventIds[task.EventId], l) {
					filters.EventIds[task.EventId] = append(filters.EventIds[task.EventId], l)
				}
			}
		}
	}

	subset := Filters{
		EventIds:  make(map[string][]string),
		ObjectIds: make(map[string][]string),
	}

	for k, v := range filters.EventIds {
		if slices.Contains(v, "malicious") {
			subset.EventIds[k] = v
		}

		if slices.Contains(v, "process") && slices.Contains(v, "event") {
			fmt.Fprintf(os.Stderr, "WARN Event filter %s contains both process and event labels\n", k)
		}
	}

	for k, v := range filters.ObjectIds {
		if slices.Contains(v, "malicious") {
			subset.ObjectIds[k] = v
		}

		if slices.Contains(v, "process") && slices.Contains(v, "event") {
			fmt.Fprintf(os.Stderr, "WARN Object filter %s contains both process and event labels\n", k)
		}
	}

	return subset
}

func readStdin(stream chan string) {
	var line string

	scanner := bufio.NewScanner(os.Stdin)
	for {
		scanner.Scan()
		line = scanner.Text()
		if line == "" {
			break
		}

		stream <- line
	}

	close(stream)
}

func main() {
	var stripFields bool
	var selectLabel string

	flag.BoolVar(&stripFields, "strip", false, "Minimize the output by stipping most of the fields.")
	flag.StringVar(&selectLabel, "label", "", "Only match events that have this label.")
	flag.Parse()

	tasks, err := loadTasks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load the tasks.json file: %s\n", err)
		os.Exit(1)
	}

	filters := makeFilters(tasks)

	stream := make(chan string, 5000)
	go readStdin(stream)

	for line := range stream {
		match := []string{}

		actorIdMatch := extractActorId.FindStringSubmatch(line)
		eventIdMatch := extractEventId.FindStringSubmatch(line)

		if len(actorIdMatch) != 2 || len(eventIdMatch) != 2 {
			continue
		}

		if l, ok := filters.ObjectIds[actorIdMatch[1]]; ok {
			match = append(match, l...)
		}
		if l, ok := filters.EventIds[eventIdMatch[1]]; ok {
			match = append(match, l...)
		}

		if selectLabel != "" && !slices.Contains(match, selectLabel) {
			continue
		}

		if len(match) > 0 {
			if stripFields {
				var data LogLine
				json.Unmarshal([]byte(line), &data)
				line, _ := json.Marshal(data)
				fmt.Println(string(line))
			} else {
				fmt.Println(line)
			}
		}
	}
}
