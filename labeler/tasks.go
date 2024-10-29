package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	satori "github.com/satori/go.uuid"
)

var labelingSets = []LabelSet{
	{
		name: "Event outcome",
		options: []string{
			"benign",
			"malicious",
		},
		labels: []string{
			"Benign",
			"Malicious",
		},
	},
	{
		name: "Source",
		options: []string{
			"ground",
			"anomaly",
			"correlated",
			"invalid",
		},
		labels: []string{
			"Ground truth",
			"Major anomaly",
			"Correlated event",
			"Invalid correlation",
		},
	},
	{
		name: "Actor",
		options: []string{
			"red",
			"admin",
		},
		labels: []string{
			"Red team",
			"Administrator",
		},
	},
	{
		name: "Timeline",
		options: []string{
			"prior",
			"day1",
			"day2",
			"day3",
		},
		labels: []string{
			"Prior to red team campaign",
			"Campaign day 1",
			"Campaign day 2",
			"Campaign day 3",
		},
	},
}

type LabelSet struct {
	name    string
	options []string
	labels  []string
}

type LabelingTask struct {
	ActionType     string                   `json:"action"`
	ActorId        string                   `json:"actor_id"`
	Annotations    []string                 `json:"annotations"`
	EventId        string                   `json:"event_id"`
	Hostname       string                   `json:"hostname"`
	Labels         []string                 `json:"labels"`
	LogEntry       string                   `json:"log"`
	ObjectId       string                   `json:"object_id"`
	ObjectType     string                   `json:"object"`
	ParentObjectId string                   `json:"parent_object_id"`
	Pid            int                      `json:"pid"`
	Ppid           int                      `json:"ppid"`
	ProcessTable   LabelingTaskProcessTable `json:"proces_table"`
	Raw            []string                 `json:"raw"`
	Timestamp      string                   `json:"timestamp"`

	TaskId string `json:"task_id"`
}

type LabelingTaskProcessTable struct {
	Children []ProcessInfo `json:"children"`
	Parent   ProcessInfo   `json:"parent"`
	Process  ProcessInfo   `json:"process"`
	Siblings []ProcessInfo `json:"siblings"`
}

type ProcessInfo struct {
	CommandLine     string `json:"command_line"`
	Create          string `json:"create"`
	Error           string `json:"error"`
	EventId         string `json:"event_id"`
	Hostname        string `json:"hostname"`
	ObjectId        string `json:"object_id"`
	ParentObjectId  string `json:"parent_object_id"`
	Pid             int    `json:"pid"`
	Ppid            int    `json:"ppid"`
	Principal       string `json:"principal"`
	Terminate       string `json:"terminate"`
	TerminateReason string `json:"terminate_reason"`
	User            string `json:"user"`
}

func (s LabelSet) NextOption(current string) string {
	if current == "" {
		return s.options[0]
	}

	for i, option := range s.options {
		if current == option {
			if i != len(s.options)-1 {
				return s.options[i+1]
			}
		}
	}

	return current
}

func (s LabelSet) PrevOption(current string) string {
	for i, option := range s.options {
		if current == option {
			if i > 0 {
				return s.options[i-1]
			}
		}
	}

	return ""
}

func (t *LabelingTask) Id() string {
	if t.TaskId == "" {
		t.TaskId = satori.NewV4().String()
	}

	return t.TaskId
}

func (t LabelingTask) Title() string {
	if t.FullyLoaded() {
		return fmt.Sprintf("%s pid=%d", t.ShortHostname(), t.Pid)
	} else {
		return "Incomplete event"
	}
}

func (t LabelingTask) Description() string {
	return t.Timestamp
}

func (t LabelingTask) FilterValue() string {
	return "fff"
}

func (t LabelingTask) ShortHostname() string {
	return strings.Replace(t.Hostname, ".systemia.com", "", 1)
}

func (t LabelingTask) FullyLoaded() bool {
	if t.ActorId == "" {
		return false
	}

	if t.EventId == "" {
		return false
	}

	if t.Hostname == "" {
		return false
	}

	if t.Pid == 0 {
		return false
	}

	if t.Ppid == 0 {
		return false
	}

	if t.Timestamp == "" {
		return false
	}

	return true
}

func (p ProcessInfo) Empty() bool {
	if p.Error != "" {
		return true
	}

	return p.EventId == ""
}

func (p ProcessInfo) GetCommandLine() string {
	if p.Error != "" {
		return fmt.Sprintf("Error :: %s", p.Error)
	}

	return p.CommandLine
}

func (p ProcessInfo) GetExecutable() string {
	var path string

	if p.CommandLine == "" {
		return ""
	}

	if p.CommandLine[0] == '"' {
		path = strings.SplitN(p.CommandLine, `"`, 3)[1]
	} else {
		path = strings.SplitN(p.CommandLine, " ", 2)[0]
	}

	if strings.Contains(path, "\\") {
		parts := strings.Split(path, "\\")
		return parts[len(parts)-1]
	} else {
		return path
	}
}

func (p ProcessInfo) LabelingTask() LabelingTask {
	task := LabelingTask{
		ActionType:     "CREATE",
		ActorId:        p.ParentObjectId,
		Annotations:    []string{},
		EventId:        p.EventId,
		Hostname:       p.Hostname,
		Labels:         []string{},
		LogEntry:       "",
		ObjectType:     "PROCESS",
		ObjectId:       p.ObjectId,
		ParentObjectId: p.ParentObjectId,
		Pid:            p.Pid,
		Ppid:           p.Ppid,
		Raw:            []string{},
		Timestamp:      p.Create,
	}

	task.Id()
	return task
}

func (p ProcessInfo) String() string {
	return fmt.Sprintf("%-5s %s",
		fmt.Sprintf("%d", p.Pid),
		p.GetCommandLine())
}

func loadTasks() []LabelingTask {
	fmt.Println(":: Loading labeling tasks...")
	tasksInput, err := ioutil.ReadFile("./tasks.json")
	if err != nil {
		fmt.Printf("Failed to open tasks.json: %s\n", err)
		return []LabelingTask{}
	}

	var initial, processed []LabelingTask
	json.Unmarshal(tasksInput, &initial)

	for _, task := range initial {
		// Ensure the task ID is set to ensure object lookups and
		// comparison operations work as expected.
		task.Id()

		if !task.FullyLoaded() {
			err := parseTaskRaw(&task)
			if err != nil {
				fmt.Printf("- Skipping labeling task due to: %s\n%s\n", err, task)
				continue
			}
		}

		processed = append(processed, task)
	}

	return processed
}

func parseTaskRaw(task *LabelingTask) error {
	var data struct {
		Action    string `json:"action"`
		ActorId   string `json:"actorID"`
		Hostname  string `json:"hostname"`
		Id        string `json:"id"`
		Object    string `json:"object"`
		ObjectId  string `json:"objectID"`
		Pid       int    `json:"pid"`
		Ppid      int    `json:"ppid"`
		Timestamp string `json:"timestamp"`
	}

	for _, line := range task.Raw {
		err := json.Unmarshal([]byte(line), &data)
		if err != nil {
			return fmt.Errorf("Failed to parse JSON: %w", err)
		}

		if task.ActorId != "" && task.ActorId != data.ActorId {
			return fmt.Errorf("The task contains multiple actorID values: %s, %s", task.ActorId, data.ActorId)
		} else {
			task.ActorId = data.ActorId
		}

		if task.EventId == "" {
			task.EventId = data.Id
		}

		if task.Hostname != "" && task.Hostname != data.Hostname {
			return fmt.Errorf("The task contains multiple hostname values: %s, %s", task.Hostname, data.Hostname)
		} else {
			task.Hostname = data.Hostname
		}

		if task.Timestamp == "" {
			task.Timestamp = data.Timestamp
		}

		if task.Pid != 0 && task.Pid != data.Pid {
			return fmt.Errorf("The task contains multiple pid values: %s, %s", task.Pid, data.Pid)
		} else {
			task.Pid = data.Pid
		}

		if task.Ppid == 0 {
			task.Ppid = data.Ppid
		}

		if data.Object == "PROCESS" && data.Action == "CREATE" {
			task.ObjectId = data.ObjectId
		} else {
			task.ObjectId = data.ActorId
		}
	}

	return nil
}

func saveTasks(tasks []LabelingTask) {
	data, _ := json.MarshalIndent(tasks, "", "    ")

	filename := fmt.Sprintf("tasks-%s.json", time.Now().Format("20060102030405"))
	f, err := os.Create(filename)
	if err != nil {
		panic(fmt.Sprintf("Failed to create output file to save tasks: %s", filename))
	}

	defer f.Close()
	f.Write(data)
}
