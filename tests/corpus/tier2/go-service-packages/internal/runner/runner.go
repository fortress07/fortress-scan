package runner

import "os/exec"

type Runner interface {
	Run(command string) error
}

type Shell struct{}

func (Shell) Run(command string) error {
	return exec.Command("/bin/sh", "-c", command).Run()  // fsb-allow: FSB-CMD-003
}
