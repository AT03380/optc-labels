package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type PaneId int
type UiMode int

const (
	MODE_VIEW UiMode = iota
	MODE_LABEL
	MODE_ENQUEUE_CHILDREN
	MODE_ENQUEUE_PARENT
	MODE_ENQUEUE_PROPAGATE
)

const (
	PANE_ID_QUEUE PaneId = iota
	PANE_ID_DETAILS
	PANE_ID_TREE
	PANE_ID_ANNOTATIONS
)

const (
	colorActive   = lipgloss.Color("#90BC64")
	colorBlue     = lipgloss.Color("#53A1E1")
	colorGrey     = lipgloss.Color("#666666")
	colorInactive = lipgloss.Color("#333333")
	colorRed      = lipgloss.Color("#F06A41")
	colorWhite    = lipgloss.Color("#FFFFFF")
	colorWarn     = lipgloss.Color("#C1A000")
)

var (
	styleHighlightBlue = lipgloss.NewStyle().
				Background(colorBlue).
				Foreground(colorWhite)

	styleHighlightGreen = lipgloss.NewStyle().
				Background(colorActive).
				Foreground(colorWhite)

	styleHighlightGrey = lipgloss.NewStyle().
				Background(colorGrey).
				Foreground(colorWhite)

	styleHighlightRed = lipgloss.NewStyle().
				Background(colorRed).
				Foreground(colorWhite)

	styleHighlightWarn = lipgloss.NewStyle().
				Background(colorWarn).
				Foreground(colorWhite)

	styleLabel = lipgloss.NewStyle().
			BorderStyle(lipgloss.Border{Left: "▌"}).
			BorderForeground(colorActive).
			Foreground(colorActive)

	styleLabelActive = lipgloss.NewStyle().
				Background(colorActive).
				BorderForeground(colorActive).
				BorderStyle(lipgloss.Border{Left: "█"}).
				Foreground(colorWhite)

	stylePane = lipgloss.NewStyle().
			BorderStyle(lipgloss.OuterHalfBlockBorder()).
			BorderForeground(colorInactive)

	stylePaneActive = stylePane.BorderForeground(colorActive)

	styleTextRed = lipgloss.NewStyle().
			Foreground(colorRed)

	styleTitle = lipgloss.NewStyle().
			Background(colorInactive).
			Foreground(colorWhite).
			Padding(0, 1).
			Width(20).
			Bold(true)

	styleTitleActive = styleTitle.Background(colorActive)

	styleWrapper = lipgloss.NewStyle().Padding(1).PaddingBottom(0)
)

var labelColors = map[string]lipgloss.Style{
	"admin":     styleHighlightBlue,
	"benign":    styleHighlightGreen,
	"malicious": styleHighlightRed,
	"red":       styleHighlightRed,
	"invalid":   styleHighlightGrey,
}

var propagateSkipLabels = []string{
	"anomaly",
	"correlated",
	"ground",
	"invalid",
}

type model struct {
	mode UiMode

	labelingTasks []LabelingTask
	lookupChan    chan *LabelingTask

	activePane     PaneId
	boxAnnotations lipgloss.Style
	boxDetails     lipgloss.Style
	boxFullscreen  lipgloss.Style
	boxQueue       lipgloss.Style
	boxTree        lipgloss.Style

	annotationsViewport viewport.Model
	detailsViewport     viewport.Model
	labelingPaging      int
	labelingQueue       list.Model
	labelingViewport    viewport.Model
	treeViewport        viewport.Model

	confirmModal  ConfirmModal
	labelsStaging map[string]string
}

type refreshMsg struct{}

func initialModel(initialTasks []LabelingTask) model {
	boxAnnotations := lipgloss.NewStyle()
	boxDetails := lipgloss.NewStyle()
	boxFullscreen := lipgloss.NewStyle()
	boxQueue := lipgloss.NewStyle()
	boxTree := lipgloss.NewStyle()

	m := model{
		activePane:          PANE_ID_QUEUE,
		annotationsViewport: viewport.New(1, 1),
		boxAnnotations:      boxAnnotations,
		boxDetails:          boxDetails,
		boxFullscreen:       boxFullscreen,
		boxQueue:            boxQueue,
		boxTree:             boxTree,
		detailsViewport:     viewport.New(1, 1),
		labelingPaging:      0,
		labelingTasks:       initialTasks,
		labelingViewport:    viewport.New(1, 1),
		labelsStaging:       make(map[string]string),
		lookupChan:          make(chan *LabelingTask, 100),
		mode:                MODE_VIEW,
		treeViewport:        viewport.New(1, 1),
	}

	m = m.createLabelingQueue(initialTasks)
	m.lookupChan <- m.CurrentLabelingTask()

	return m
}

func addLabelPadding(label string) string {
	half := fmt.Sprintf("%s%s", label, strings.Repeat(" ", (15-len(label))/2))
	return fmt.Sprintf("[%s%s]", strings.Repeat(" ", 15-len(half)), half)
}

func fitWidth(s string, w int, pad string, padFirst bool) string {
	var r string

	s = pad + s

	if w < 1 {
		return s
	}

	for s != "" {
		if r != "" {
			r += "\n"
		}

		if w > len(s) {
			w = len(s)
		}

		r, s = r+s[0:w], s[w:len(s)]

		if len(s) > 0 {
			s = pad + s
		}
	}

	if !padFirst {
		r = r[len(pad):len(r)]
	}

	return r
}

func generateAnnotationsContent(task LabelingTask, w int, allTasks []LabelingTask) string {
	var benign, malicious int
	var contents strings.Builder
	var otherLabelsContents strings.Builder

	for _, other := range allTasks {
		if other.TaskId == task.TaskId {
			continue
		}

		if task.ProcessTable.Process.EventId == "" {
			continue
		}

		if task.ProcessTable.Process.EventId != other.ProcessTable.Process.EventId {
			continue
		}

		if slices.Contains(other.Labels, "benign") {
			benign += 1
		}

		if slices.Contains(other.Labels, "malicious") {
			malicious += 1
		}
	}

	if benign > 0 {
		otherLabelsContents.WriteString(fmt.Sprintf(
			" Process is labeled as %s in %d other events.\n",
			styleHighlightGreen.Render("benign"),
			benign))
	}

	if malicious > 0 {
		otherLabelsContents.WriteString(fmt.Sprintf(
			" Process is labeled as %s in %d other events.\n",
			styleHighlightRed.Render("malicious"),
			malicious))
	}

	if otherLabelsContents.String() != "" {
		contents.WriteString(styleLabel.Render("Labeled event"))
		contents.WriteString("\n")
		contents.WriteString(otherLabelsContents.String())
	}

	if len(task.Annotations) > 0 {
		contents.WriteString(styleLabel.Render("Annotations"))

		for _, annotation := range task.Annotations {
			contents.WriteString("\n")
			contents.WriteString(fitWidth(annotation, w-1, " ", true))
		}

		contents.WriteString("\n")
	}

	if task.LogEntry != "" {
		contents.WriteString(styleLabel.Render("Log entry"))
		contents.WriteString("\n")
		contents.WriteString(fitWidth(task.LogEntry, w-1, " ", true))
		contents.WriteString("\n")
	}

	if c := task.ProcessTable.Process.GetCommandLine(); c != "" {
		contents.WriteString(styleLabel.Render("Command line"))
		contents.WriteString("\n")
		contents.WriteString(fitWidth(c, w-1, " ", true))
		contents.WriteString("\n")
	}

	if c := task.ProcessTable.Parent.GetCommandLine(); c != "" {
		contents.WriteString(styleLabel.Render("Parent command line"))
		contents.WriteString("\n")
		contents.WriteString(fitWidth(c, w-1, " ", true))
		contents.WriteString("\n")
	}

	return contents.String()
}

func generateTreeContent(task LabelingTask, w int) string {
	var content strings.Builder
	var l2line string
	var l2marker string

	content.WriteString(" ▾ \n")
	content.WriteString(" ┖─ ")
	content.WriteString(fitWidth(task.ProcessTable.Parent.String(), w-2, "    ", false))
	content.WriteString("\n")

	if len(task.ProcessTable.Siblings) > 0 {
		l2marker = "┠▶"
		l2line = "┃"
	} else {
		l2marker = "┖▶"
		l2line = " "
	}

	for i, line := range strings.Split(fitWidth(task.ProcessTable.Process.String(), w-9, "", false), "\n") {
		if i == 0 {
			content.WriteString(fmt.Sprintf(
				"    %s %s\n", l2marker, styleTextRed.Render(line)))
		} else {
			content.WriteString(fmt.Sprintf(
				"    %s  %s\n", l2line, styleTextRed.Render(line)))
		}
	}

	func() {
		var l3marker string

		l := []string{}
		for _, child := range task.ProcessTable.Children {
			l = append(l, child.String())
		}
		slices.Sort(l)

		for i, c := range l {
			if i == len(l)-1 {
				l3marker = "┖─"
			} else {
				l3marker = "┠─"
			}

			for j, line := range strings.Split(fitWidth(c, w-12, "", false), "\n") {
				if j == 0 {
					content.WriteString(fmt.Sprintf("    %s  %s %s\n", l2line, l3marker, line))
				} else {
					content.WriteString(fmt.Sprintf("    %s     %s\n", l2line, line))
				}
			}
		}
	}()

	func() {
		l := []string{}
		for _, sibling := range task.ProcessTable.Siblings {
			l = append(l, sibling.String())
		}
		slices.Sort(l)

		for i, c := range l {
			if i == len(l)-1 {
				content.WriteString("    ┖─ ")
			} else {
				content.WriteString("    ┠─ ")
			}

			content.WriteString(fitWidth(c, w-2, "       ", false))
			content.WriteString("\n")
		}
	}()

	return content.String()
}

func generateDetailsContent(task LabelingTask) string {
	var contents strings.Builder
	var labels strings.Builder
	var unlabeled bool = true

	if !task.FullyLoaded() {
		return "The task does not include a raw event necessary to load process details."
	}

	if task.EventId == "" {
		return ""
	}

	contents.WriteString(styleLabel.Render("Hostname"))
	contents.WriteString("\n ")
	contents.WriteString(task.Hostname)
	contents.WriteString("\n")

	contents.WriteString(styleLabel.Render("PID (PPID)"))
	contents.WriteString("\n ")
	contents.WriteString(fmt.Sprintf("%d", task.Pid))
	contents.WriteString(" (")
	contents.WriteString(fmt.Sprintf("%d", task.Ppid))
	contents.WriteString(")")
	contents.WriteString("\n")

	if exec := task.ProcessTable.Process.GetExecutable(); exec != "" {
		contents.WriteString(styleLabel.Render("Executable"))
		contents.WriteString("\n ")
		contents.WriteString(exec)
		contents.WriteString("\n")
	}

	contents.WriteString(styleLabel.Render("Event ID"))
	contents.WriteString("\n ")
	contents.WriteString(task.EventId)
	contents.WriteString("\n")

	contents.WriteString(styleLabel.Render("Timestamp"))
	contents.WriteString("\n ")
	contents.WriteString(task.Timestamp)
	contents.WriteString("\n")

	for _, label := range task.Labels {
		if label == "benign" || label == "malicious" {
			unlabeled = false
		}

		labels.WriteString(" ")

		if color, ok := labelColors[label]; ok {
			labels.WriteString(color.Render(addLabelPadding(label)))
		} else {
			labels.WriteString(addLabelPadding(label))
		}

		labels.WriteString("\n")
	}

	if unlabeled {
		labels.WriteString(" ")
		labels.WriteString(styleHighlightWarn.Render(addLabelPadding("UNLABELED")))
		labels.WriteString("\n")
	}

	contents.WriteString(styleLabel.Render("Labels"))
	contents.WriteString("\n")
	contents.WriteString(labels.String())
	contents.WriteString("\n")

	return contents.String()
}

func renderLabelChoise(labels map[string]string, set LabelSet) string {
	var content strings.Builder

	current, _ := labels[set.name]
	if current == "" {
		content.WriteString(" ▶ - \n")
	} else {
		content.WriteString("   - \n")
	}

	for i, option := range set.options {
		if option == current {
			content.WriteString(fmt.Sprintf(" ▶ %s \n", set.labels[i]))
		} else {
			content.WriteString(fmt.Sprintf("   %s \n", set.labels[i]))
		}
	}

	return content.String()
}

func main() {
	lookupService := LookupService{}

	tasks := loadTasks()
	m := initialModel(tasks)
	p := tea.NewProgram(m)

	go func() {
		for task := range m.lookupChan {
			if ok := lookupService.Lookup(task); ok {
				p.Send(refreshMsg{})
			}
		}
	}()

	result, err := p.Run()
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	m = result.(model)
	saveTasks(m.labelingTasks)
}

func (m model) CurrentLabelingTask() *LabelingTask {
	selected := m.labelingQueue.SelectedItem()
	if selected == nil {
		return &LabelingTask{}
	}

	pointer := selected.(LabelingTask)
	for i, task := range m.labelingTasks {
		if task.Id() == pointer.Id() {
			return &m.labelingTasks[i]
		}
	}

	return &LabelingTask{}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msgType := msg.(type) {
	case tea.KeyMsg:
		switch msgType.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		return m.recalculatePaneSizes(msgType.Width, msgType.Height), nil
	}

	if m.mode == MODE_LABEL {
		return m.UpdateLabel(msg)
	}

	if m.mode == MODE_ENQUEUE_CHILDREN {
		return m.UpdateEnqueueChildren(msg)
	}

	if m.mode == MODE_ENQUEUE_PARENT {
		return m.UpdateEnqueueParent(msg)
	}

	if m.mode == MODE_ENQUEUE_PROPAGATE {
		return m.UpdateEnqueuePropagate(msg)
	}

	if m.mode == MODE_VIEW {
		return m.UpdateView(msg)
	}

	return m, nil

}

func (m model) UpdateEnqueueChildren(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msgType := msg.(type) {
	case tea.KeyMsg:
		switch msgType.String() {
		case "enter":
			if m.confirmModal.Ok() {
				task := m.CurrentLabelingTask()

				annotations := []string{
					fmt.Sprintf(
						`Correlated as child of process "%s" with event ID "%s".`,
						task.ProcessTable.Process.GetExecutable(),
						task.EventId,
					),
				}

				labels := []string{"correlated"}
				for _, label := range task.Labels {
					if slices.Contains(propagateSkipLabels, label) {
						continue
					}
					labels = append(labels, label)
				}

				m = m.enqueueProcesses(task.ProcessTable.Children, labels, annotations, false)
			}

			m.mode = MODE_VIEW
			return m, nil
		}
	}

	m.confirmModal, _ = m.confirmModal.Update(msg)
	return m, nil
}

func (m model) UpdateEnqueueParent(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msgType := msg.(type) {
	case tea.KeyMsg:
		switch msgType.String() {
		case "enter":
			if m.confirmModal.Ok() {
				task := m.CurrentLabelingTask()

				annotations := []string{
					fmt.Sprintf(
						`Correlated as parent of process "%s" with event ID "%s".`,
						task.ProcessTable.Process.GetExecutable(),
						task.EventId,
					),
				}

				labels := []string{"correlated"}
				ps := []ProcessInfo{
					task.ProcessTable.Parent,
				}

				m = m.enqueueProcesses(ps, labels, annotations, false)
			}

			m.mode = MODE_VIEW
			return m, nil
		}
	}

	m.confirmModal, _ = m.confirmModal.Update(msg)
	return m, nil
}

func (m model) UpdateEnqueuePropagate(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msgType := msg.(type) {
	case tea.KeyMsg:
		switch msgType.String() {
		case "enter":
			task := m.CurrentLabelingTask()

			if m.confirmModal.Ok() && slices.Contains(task.Labels, "malicious") {
				annotations := []string{
					fmt.Sprintf(
						`Propagated "malicious" label from process "%s" with event ID "%s".`,
						task.ProcessTable.Process.GetExecutable(),
						task.EventId,
					),
				}

				labels := []string{"correlated"}
				for _, label := range task.Labels {
					if slices.Contains(propagateSkipLabels, label) {
						continue
					}
					labels = append(labels, label)
				}

				m = m.enqueueProcesses(task.ProcessTable.Children, labels, annotations, true)
			}

			m.mode = MODE_VIEW
			return m, nil
		}
	}

	m.confirmModal, _ = m.confirmModal.Update(msg)
	return m, nil
}

func (m model) UpdateLabel(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msgType := msg.(type) {
	case tea.KeyMsg:
		switch msgType.String() {
		case "enter":
			labels := []string{}

			for _, set := range labelingSets {
				value, ok := m.labelsStaging[set.name]

				if ok && value != "" {
					labels = append(labels, value)
				}
			}

			currentTask := m.CurrentLabelingTask()
			currentTask.Labels = labels

			m.mode = MODE_VIEW
			m = m.UpdateCurrentTaskDetails(*currentTask)
			return m, nil

		case "down":
			set := labelingSets[m.labelingPaging]
			m.labelsStaging[set.name] = set.NextOption(m.labelsStaging[set.name])

		case "left":
			m.labelingPaging = (m.labelingPaging + len(labelingSets) - 1) % len(labelingSets)

		case "right":
			m.labelingPaging = (m.labelingPaging + 1) % len(labelingSets)

		case "up":
			set := labelingSets[m.labelingPaging]
			m.labelsStaging[set.name] = set.PrevOption(m.labelsStaging[set.name])
		}
	}

	return m, nil
}

func (m model) UpdateView(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msgType := msg.(type) {
	case tea.KeyMsg:
		switch msgType.String() {
		case "enter":
			m.labelsStaging = make(map[string]string)
			for _, set := range labelingSets {
				m.labelsStaging[set.name] = ""

				for _, option := range set.options {
					if slices.Contains(m.CurrentLabelingTask().Labels, option) {
						m.labelsStaging[set.name] = option
					}
				}
			}

			m.labelingPaging = 0
			m.mode = MODE_LABEL
			return m, nil

		case "f1":
			m.confirmModal = NewConfirmModal("Add parent process", colorActive)
			m.mode = MODE_ENQUEUE_PARENT
			return m, nil

		case "f5":
			m.confirmModal = NewConfirmModal("Add child processes", colorActive)
			m.mode = MODE_ENQUEUE_CHILDREN
			return m, nil

		case "f9":
			m.confirmModal = NewConfirmModal("Propagate labels", colorActive)
			m.mode = MODE_ENQUEUE_PROPAGATE
			return m, nil

		case "tab":
			m.activePane = (m.activePane + 1) % 4
			return m, nil

		case "shift+tab":
			m.activePane = (m.activePane + 4 - 1) % 4
			return m, nil
		}

	case refreshMsg:
		currentTask := m.CurrentLabelingTask()
		m = m.UpdateCurrentTaskDetails(*currentTask)
		return m, nil
	}

	if m.activePane == PANE_ID_QUEUE {
		currentTask := m.CurrentLabelingTask()

		newLabelingQueue, cmd := m.labelingQueue.Update(msg)
		m.labelingQueue = newLabelingQueue

		updatedTask := m.CurrentLabelingTask()
		if currentTask.Id() != updatedTask.Id() {
			m.lookupChan <- updatedTask
			m = m.UpdateCurrentTaskDetails(*updatedTask)
		}

		return m, cmd
	}

	if m.activePane == PANE_ID_ANNOTATIONS {
		newAnnotationsViewport, cmd := m.annotationsViewport.Update(msg)
		m.annotationsViewport = newAnnotationsViewport
		return m, cmd
	}

	if m.activePane == PANE_ID_TREE {
		newTreeViewport, cmd := m.treeViewport.Update(msg)
		m.treeViewport = newTreeViewport
		return m, cmd
	}

	if m.activePane == PANE_ID_DETAILS {
		newDetailsViewport, cmd := m.detailsViewport.Update(msg)
		m.detailsViewport = newDetailsViewport
		return m, cmd
	}

	return m, nil
}

func (m model) UpdateCurrentTaskDetails(task LabelingTask) model {
	m.annotationsViewport.SetContent(generateAnnotationsContent(task, m.annotationsViewport.Width, m.labelingTasks))
	m.treeViewport.SetContent(generateTreeContent(task, m.treeViewport.Width))
	m.detailsViewport.SetContent(generateDetailsContent(task))

	return m
}

func (m model) View() string {
	labelingStats := m.calculateLabelingStats()

	if m.mode == MODE_VIEW {
		mainRow := lipgloss.JoinHorizontal(
			lipgloss.Top,
			m.wrapPane("Event queue", m.viewQueuePane(), m.activePane == PANE_ID_QUEUE),
			m.wrapPane("Details", m.viewDetailsPane(), m.activePane == PANE_ID_DETAILS),
			m.wrapPane("Process tree", m.viewTreePane(), m.activePane == PANE_ID_TREE))

		statusRow := " " + styleTitle.Render("Status") + " "
		statusRow += fmt.Sprintf("Unlabeled: %d", labelingStats["unlabeled"])
		statusRow += "    "
		statusRow += styleHighlightGreen.Render(fmt.Sprintf(" Benign: %d ", labelingStats["benign"]))
		statusRow += "    "
		statusRow += styleHighlightRed.Render(fmt.Sprintf(" Red team: %d ", labelingStats["red"]))
		statusRow += "    "
		statusRow += styleHighlightBlue.Render(fmt.Sprintf(" Administrator: %d ", labelingStats["admin"]))

		if labelingStats["malicious"] > 0 {
			statusRow += "    "
			statusRow += fmt.Sprintf("Unclassified malicious: %d", labelingStats["malicious"])
		}

		return lipgloss.JoinVertical(
			lipgloss.Left,
			"",
			statusRow,
			mainRow,
			m.wrapPane("Annotations", m.viewAnnotationsPane(), m.activePane == PANE_ID_ANNOTATIONS))
	}

	if m.mode == MODE_LABEL {
		return m.wrapPane("Event labeling", m.viewLabelingPane(), true)
	}

	if m.mode == MODE_ENQUEUE_CHILDREN {
		return m.wrapPane("Enqueue events", m.viewEnqueueChildren(), true)
	}

	if m.mode == MODE_ENQUEUE_PARENT {
		return m.wrapPane("Enqueue events", m.viewEnqueueParent(), true)
	}

	if m.mode == MODE_ENQUEUE_PROPAGATE {
		return m.wrapPane("Enqueue events", m.viewEnqueuePropagate(), true)
	}

	return ""
}

func (m model) addTask(newTask LabelingTask) (model, bool) {
	var exists, updated bool

	for _, task := range m.labelingTasks {
		if task.EventId == newTask.EventId {
			exists = true
			break
		}
	}

	if !exists {
		m.labelingTasks = append(m.labelingTasks, newTask)
		updated = true
	}

	return m, updated
}

func (m model) calculateLabelingStats() map[string]int {
	stats := map[string]int{
		"admin":     0,
		"benign":    0,
		"malicious": 0,
		"red":       0,
		"unlabeled": 0,
	}

	for _, task := range m.labelingTasks {
		if !task.FullyLoaded() {
			continue
		}

		if slices.Contains(task.Labels, "benign") {
			stats["benign"] += 1
		} else if slices.Contains(task.Labels, "malicious") {
			if slices.Contains(task.Labels, "admin") {
				stats["admin"] += 1
			} else if slices.Contains(task.Labels, "red") {
				stats["red"] += 1
			} else {
				stats["malicious"] += 1
			}
		} else {
			stats["unlabeled"] += 1
		}
	}

	return stats
}

func (m model) createLabelingQueue(tasks []LabelingTask) model {
	labelingQueueItems := make([]list.Item, len(tasks))
	for i, task := range tasks {
		labelingQueueItems[i] = task
	}

	labelingQueue := list.New(labelingQueueItems, list.NewDefaultDelegate(), 1, 1)
	labelingQueue.SetHeight(m.labelingQueue.Height())
	labelingQueue.SetShowHelp(false)
	labelingQueue.SetShowTitle(false)
	labelingQueue.SetWidth(m.labelingQueue.Width())

	m.labelingQueue = labelingQueue
	m = m.UpdateCurrentTaskDetails(*m.CurrentLabelingTask())

	return m
}

func (m model) enqueueProcesses(ps []ProcessInfo, labels []string, annotations []string, recursive bool) model {
	var process ProcessInfo
	var refresh, updated bool

	lookupService := LookupService{}

	for len(ps) > 0 {
		if len(ps) == 1 {
			process, ps = ps[0], []ProcessInfo{}
		} else {
			process, ps = ps[0], ps[1:len(ps)]
		}

		if process.Empty() {
			continue
		}

		task := process.LabelingTask()
		task.Annotations = annotations
		task.Labels = labels
		lookupService.Lookup(&task)

		m, updated = m.addTask(task)
		if updated {
			refresh = true
		}

		if recursive && len(task.ProcessTable.Children) > 0 {
			for _, child := range task.ProcessTable.Children {
				ps = append(ps, child)
			}
		}
	}

	if refresh {
		m = m.createLabelingQueue(m.labelingTasks)
	}

	return m
}

func (m model) recalculatePaneSizes(width, height int) model {
	const borderWidth = 1
	const paddingWidth = 1
	const titleHeight = 1

	const annotationsHeight = 20
	const detailsWidth = 50
	const queueWidth = 45
	const statusBarHeight = 2

	height -= statusBarHeight

	m.boxAnnotations = m.boxAnnotations.Height(annotationsHeight).Width(width - (2 * borderWidth) - (2 * paddingWidth))
	m.annotationsViewport.Height = annotationsHeight
	m.annotationsViewport.Width = width - (2 * borderWidth) - (2 * paddingWidth)

	remainingHeight := height - annotationsHeight - (4 * borderWidth) - (2 * paddingWidth) - (2 * titleHeight)
	m.boxQueue = m.boxQueue.Height(remainingHeight).Width(queueWidth)
	m.labelingQueue.SetSize(queueWidth-2, remainingHeight)

	remainingWidth := width - queueWidth - (4 * borderWidth) - (2 * paddingWidth)
	m.boxDetails = m.boxDetails.Height(remainingHeight).Width(detailsWidth)
	m.detailsViewport.Height = remainingHeight - (2 * borderWidth)
	m.detailsViewport.Width = detailsWidth - (2 * borderWidth) - (2 * paddingWidth)

	remainingWidth -= detailsWidth + (2 * borderWidth) + (2 * paddingWidth)
	m.boxTree = m.boxTree.Height(remainingHeight).Width(remainingWidth - borderWidth - paddingWidth)
	m.treeViewport.Height = remainingHeight - (2 * borderWidth)
	m.treeViewport.Width = remainingWidth - (2 * borderWidth) - (2 * paddingWidth)

	m.boxFullscreen = m.boxFullscreen.
		Height(height - (2 * borderWidth) - (2 * paddingWidth)).
		Width(width - (2 * borderWidth) - (2 * paddingWidth))

	return m
}

func (m model) viewAnnotationsPane() string {
	return m.boxAnnotations.Render(m.annotationsViewport.View())
}

func (m model) viewEnqueueChildren() string {
	var content strings.Builder

	task := m.CurrentLabelingTask()
	if len(task.ProcessTable.Children) < 1 {
		return m.boxFullscreen.Render("\n No child processes found.\n")
	}

	content.WriteString("\n Add child processes of the current event to the queue for manual analysis?\n")
	content.WriteString(fmt.Sprintf("\n Number of new events: %d\n\n", len(task.ProcessTable.Children)))
	content.WriteString(m.confirmModal.View())

	return m.boxFullscreen.Render(content.String())
}

func (m model) viewEnqueueParent() string {
	var content strings.Builder

	task := m.CurrentLabelingTask()
	if task.ProcessTable.Parent.Empty() {
		return m.boxFullscreen.Render("\n Information about the parent process is not available.\n")
	}

	content.WriteString("\n Add the parent process of the current event to the queue for manual analysis?\n\n")
	content.WriteString(m.confirmModal.View())

	return m.boxFullscreen.Render(content.String())
}

func (m model) viewEnqueuePropagate() string {
	var content strings.Builder
	var labelsRender strings.Builder

	task := m.CurrentLabelingTask()
	if len(task.ProcessTable.Children) < 1 {
		return m.boxFullscreen.Render("\n No child processes found.\n")
	}

	if !slices.Contains(task.Labels, "malicious") {
		return m.boxFullscreen.Render("\n Cannot propagate the label: the current event must be labeled as malicious.\n")
	}

	labels := []string{"correlated"}
	for _, label := range task.Labels {
		if slices.Contains(propagateSkipLabels, label) {
			continue
		}
		labels = append(labels, label)
	}

	for i, label := range labels {
		if i != 0 {
			labelsRender.WriteString(", ")
		}

		if color, ok := labelColors[label]; ok {
			labelsRender.WriteString(color.Render(addLabelPadding(label)))
		} else {
			labelsRender.WriteString(addLabelPadding(label))
		}
	}

	content.WriteString("\n Recursively propagate current labels to all child processes?\n")
	content.WriteString(fmt.Sprintf("\n Propagating the following labels: %s\n\n", labelsRender.String()))
	content.WriteString(m.confirmModal.View())

	return m.boxFullscreen.Render(content.String())
}

func (m model) viewLabelingPane() string {
	var contents strings.Builder

	task := m.CurrentLabelingTask()

	if !task.FullyLoaded() {
		return m.boxFullscreen.Render("\n Event is not fully loaded with all details necessary for labeling.\n")
	}

	contents.WriteString(styleLabel.Render("Event ID"))
	contents.WriteString("\n ")
	contents.WriteString(task.EventId)
	contents.WriteString("\n")

	if len(task.Raw) > 0 {
		contents.WriteString(styleLabel.Render("Raw event"))
		contents.WriteString("\n")
		contents.WriteString(fitWidth(task.Raw[0], m.boxFullscreen.GetWidth()-2, " ", true))
		contents.WriteString("\n")
	}

	contents.WriteString(styleLabel.Render("Timestamp"))
	contents.WriteString("\n ")
	contents.WriteString(task.Timestamp)
	contents.WriteString("\n\n")

	widgets := []string{}
	for i, set := range labelingSets {
		var widget strings.Builder

		if m.labelingPaging == i {
			widget.WriteString(styleLabelActive.Render(set.name + " "))
		} else {
			widget.WriteString(styleLabel.Render(set.name + " "))
		}

		widget.WriteString("\n")
		widget.WriteString(renderLabelChoise(m.labelsStaging, set))

		widgets = append(widgets, widget.String())
	}

	contents.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Top,
		widgets...))

	return m.boxFullscreen.Render(contents.String())
}

func (m model) viewQueuePane() string {
	return m.boxQueue.Render(m.labelingQueue.View())
}

func (m model) viewTreePane() string {
	return m.boxTree.Render(m.treeViewport.View())
}

func (m model) viewDetailsPane() string {
	return m.boxDetails.Render(fmt.Sprintf(
		"%s\n                                           %3.f%%",
		m.detailsViewport.View(),
		m.detailsViewport.ScrollPercent()*100))
}

func (m model) wrapPane(title, content string, active bool) string {
	if active {
		return styleWrapper.Render(fmt.Sprintf(
			"%s\n%s",
			styleTitleActive.Render(title),
			stylePaneActive.Render(content)))
	} else {
		return styleWrapper.Render(fmt.Sprintf(
			"%s\n%s",
			styleTitle.Render(title),
			stylePane.Render(content)))
	}

}
