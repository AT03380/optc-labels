package main

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ConfirmModal struct {
	Options       []string
	index         int
	styleActive   lipgloss.Style
	styleInactive lipgloss.Style
}

func NewConfirmModal(message string, activeColor lipgloss.Color) ConfirmModal {
	border := lipgloss.InnerHalfBlockBorder()

	styleActive := lipgloss.NewStyle().
		Background(activeColor).
		Bold(true).
		Border(border).
		BorderForeground(activeColor).
		Foreground(lipgloss.Color("white"))

	styleInactive := lipgloss.NewStyle().
		Background(lipgloss.Color("#333333")).
		Border(border).
		BorderForeground(lipgloss.Color("#333333")).
		Foreground(lipgloss.Color("#999999"))

	options := []string{
		message,
		"Cancel",
	}

	return ConfirmModal{
		Options:       options,
		index:         0,
		styleActive:   styleActive,
		styleInactive: styleInactive,
	}
}

func (m ConfirmModal) Init() tea.Cmd {
	return nil
}

func (m ConfirmModal) Ok() bool {
	return m.index == 0
}

func (m ConfirmModal) Selected() string {
	return m.Options[m.index]
}

func (m ConfirmModal) Update(msg tea.Msg) (ConfirmModal, tea.Cmd) {
	if len(m.Options) < 1 {
		return m, nil
	}

	switch msgType := msg.(type) {
	case tea.KeyMsg:
		switch msgType.String() {
		case "left":
			m.index = (m.index + 1) % len(m.Options)
			return m, nil

		case "right":
			m.index = (m.index + len(m.Options) - 1) % len(m.Options)
			return m, nil
		}
	}

	return m, nil
}

func (m ConfirmModal) View() string {
	var style lipgloss.Style

	buttons := []string{
		" ",
		m.styleActive.Render(""),
	}

	for i, option := range m.Options {
		if i == m.index {
			style = m.styleActive
		} else {
			style = m.styleInactive
		}

		buttons = append(buttons, style.Render(option))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, buttons...)
}
