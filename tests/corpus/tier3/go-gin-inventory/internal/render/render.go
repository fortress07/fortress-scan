package render

import (
	"html/template"
	"io"
)

var raw = template.Must(template.New("note").Parse(`<div class="note">{{ . }}</div>`))

func Note(writer io.Writer, note string) error {
	return raw.Execute(writer, template.HTML(note))
}

func Escaped(writer io.Writer, note string) error {
	return raw.Execute(writer, note)
}
