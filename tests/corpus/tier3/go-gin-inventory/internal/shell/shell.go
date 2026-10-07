package shell

import (
	"os/exec"
)

func Run(command string) error {
	return exec.Command("sh", "-c", command).Run() // fsb-allow: FSB-CMD-003
}
