package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type LookupService struct {
}

type lookupProcessInfo struct {
	CommandLine     string
	Create          string
	EventId         string
	Hostname        string
	ObjectId        string
	ParentObjectId  string
	Pid             int
	Ppid            int
	Principal       string
	Terminate       string
	TerminateReason string
	User            string
}

type lookupResponse struct {
	Process  lookupProcessInfo
	Children []lookupProcessInfo
}

func (l LookupService) Lookup(task *LabelingTask) bool {
	if task.ProcessTable.Process.EventId != "" {
		return false
	}

	if task.ProcessTable.Process.ObjectId != "" {
		return false
	}

	if task.ProcessTable.Process.Error != "" {
		return false
	}

	if !task.FullyLoaded() {
		task.ProcessTable.Process.Error = "The task does not include a raw event necessary to load process details."
		task.ProcessTable.Process.Pid = -1
		return true
	}

	if pidInfo, err := l.getProcessDetails(task.Hostname, task.Timestamp, task.Pid, task.ObjectId); err == nil {
		if task.ProcessTable.Process.ObjectId != pidInfo.Process.ObjectId {
			task.ProcessTable.Process = pidInfo.Process.ProcessInfo()

			task.ProcessTable.Children = []ProcessInfo{}
			for _, childInfo := range pidInfo.Children {
				task.ProcessTable.Children = append(task.ProcessTable.Children, childInfo.ProcessInfo())
			}
		}
	} else {
		task.ProcessTable.Process.Error = fmt.Sprintf("%s", err.Error())
		task.ProcessTable.Process.Pid = -1
	}

	if ppidInfo, err := l.getProcessDetails(task.Hostname, task.Timestamp, task.Ppid, task.ParentObjectId); err == nil {
		if task.ProcessTable.Parent.ObjectId != ppidInfo.Process.ObjectId {
			task.ProcessTable.Parent = ppidInfo.Process.ProcessInfo()

			task.ProcessTable.Siblings = []ProcessInfo{}
			for _, childInfo := range ppidInfo.Children {
				if childInfo.ObjectId == task.ProcessTable.Process.ObjectId {
					continue
				}

				task.ProcessTable.Siblings = append(task.ProcessTable.Siblings, childInfo.ProcessInfo())
			}
		}
	} else {
		task.ProcessTable.Parent.Error = fmt.Sprintf("%s", err.Error())
		task.ProcessTable.Parent.Pid = -1
	}

	return true
}

func (l LookupService) getProcessDetails(hostname string, timestamp string, pid int, objectId string) (lookupResponse, error) {
	var data []lookupResponse

	params := url.Values{}
	params.Add("children", "yes")
	params.Add("hostname", hostname)
	params.Add("pid", fmt.Sprintf("%d", pid))
	params.Add("t", timestamp)

	if objectId != "" {
		params.Add("object_id", objectId)
	}

	addr, _ := url.Parse("http://localhost:29701/lookup")
	addr.RawQuery = params.Encode()

	req, _ := http.NewRequest(http.MethodGet, addr.String(), nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return lookupResponse{}, err
	}

	body, _ := ioutil.ReadAll(res.Body)

	if err := json.Unmarshal(body, &data); err != nil {
		return lookupResponse{}, err
	}

	if len(data) < 1 {
		return lookupResponse{}, fmt.Errorf("Lookup did not find any processes")
	}

	if len(data) > 1 {
		return lookupResponse{}, fmt.Errorf("Lookup returned %d processes", len(data))
	}

	return data[0], nil
}

func (i lookupProcessInfo) ProcessInfo() ProcessInfo {
	return ProcessInfo{
		CommandLine:     i.CommandLine,
		Create:          i.Create,
		EventId:         i.EventId,
		Hostname:        i.Hostname,
		ObjectId:        i.ObjectId,
		ParentObjectId:  i.ParentObjectId,
		Pid:             i.Pid,
		Ppid:            i.Ppid,
		Principal:       i.Principal,
		Terminate:       i.Terminate,
		TerminateReason: i.TerminateReason,
		User:            i.User,
	}
}
